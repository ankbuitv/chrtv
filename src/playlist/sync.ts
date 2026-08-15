import { parsePlaylist, PlaylistError } from './parser';
import { sha256Hex } from '../utils/crypto';
import { getSetting, setSetting } from '../db/settings';
import type { Env } from '../types';

export interface SyncResult {
  status: 'ok' | 'skipped' | 'failed' | 'busy';
  channelCount?: number;
  categoryCount?: number;
  hash?: string;
  error?: string;
}

const SYNC_LOCK_TTL = 5 * 60; // seconds
const FETCH_TIMEOUT_MS = 30_000;

/**
 * Sync the GitHub playlist into D1.
 * - hash check: unchanged playlist => no DB rewrite
 * - a failed parse NEVER touches the existing channel set (old version stays live)
 * - upserts keep stable channel ids; channels missing from the new playlist are deactivated
 * - a settings-based lock (with TTL) prevents concurrent syncs
 */
export async function syncPlaylist(env: Env, trigger: 'cron' | 'admin'): Promise<SyncResult> {
  const db = env.DB;
  const now = Math.floor(Date.now() / 1000);

  // --- acquire lock (compare-and-set on settings row) ---
  const lockToken = crypto.randomUUID();
  const cutoff = now - SYNC_LOCK_TTL;
  const lock = await db
    .prepare(
      `UPDATE settings SET value = ?
       WHERE key = 'sync_lock' AND (value = '' OR CAST(substr(value, 38) AS INTEGER) < ?)`,
    )
    .bind(`${lockToken}|${now}`, cutoff)
    .run();
  if (!lock.meta || lock.meta.changes === 0) {
    await logSync(db, now, 'busy', trigger, 0, 0, '', 'sync already in progress');
    return { status: 'busy', error: 'sync already in progress' };
  }

  try {
    return await doSync(env, trigger, now);
  } finally {
    await db.prepare(`UPDATE settings SET value = '' WHERE key = 'sync_lock' AND value = ?`).bind(`${lockToken}|${now}`).run();
  }
}

async function doSync(env: Env, trigger: 'cron' | 'admin', startedAt: number): Promise<SyncResult> {
  const db = env.DB;
  let text: string;
  try {
    const res = await fetch(env.PLAYLIST_URL, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'User-Agent': 'CHRTV-sync/1.0', Accept: 'text/plain, application/x-mpegurl, */*' },
      cf: { cacheTtl: 0 },
    });
    if (!res.ok) throw new Error(`playlist fetch HTTP ${res.status}`);
    text = await res.text();
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'fetch failed';
    await failSync(db, startedAt, trigger, msg);
    return { status: 'failed', error: msg };
  }

  const hash = await sha256Hex(text);
  const prevHash = await getSetting(db, 'playlist_hash');
  if (hash === prevHash) {
    await logSync(db, startedAt, 'skipped', trigger, 0, 0, hash, '');
    await setSetting(db, 'last_sync', String(startedAt));
    await setSetting(db, 'sync_status', 'ok');
    return { status: 'skipped', hash };
  }

  let parsed;
  try {
    parsed = await parsePlaylist(text);
  } catch (err) {
    const msg = err instanceof PlaylistError ? err.message : 'parse failed';
    await failSync(db, startedAt, trigger, msg);
    return { status: 'failed', error: msg };
  }

  const seq = Number(await getSetting(db, 'sync_seq')) + 1;
  const nowSec = Math.floor(Date.now() / 1000);

  try {
    // Categories first (need their ids)
    const catStmts = parsed.categories.map((name, i) =>
      db
        .prepare('INSERT INTO categories (name, position) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET position = excluded.position')
        .bind(name, i),
    );
    if (catStmts.length > 0) await db.batch(catStmts);
    const { results: catRows } = await db.prepare('SELECT id, name FROM categories').all<{ id: number; name: string }>();
    const catId = new Map(catRows.map((c) => [c.name, c.id]));

    // Channel upserts — batch() runs as an implicit transaction per batch.
    const stmts: D1PreparedStatement[] = [];
    for (const ch of parsed.channels) {
      stmts.push(
        db
          .prepare(
            `INSERT INTO channels (id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, url = excluded.url, tvg_id = excluded.tvg_id, tvg_logo = excluded.tvg_logo,
               category_id = excluded.category_id, position = excluded.position, active = 1,
               sync_seq = excluded.sync_seq, updated_at = excluded.updated_at`,
          )
          .bind(ch.id, ch.name, ch.url, ch.tvgId, ch.tvgLogo, catId.get(ch.group) ?? null, ch.position, seq, nowSec, nowSec),
      );
    }
    // Deactivate channels not present in this sync + assign xtream ids to new rows.
    stmts.push(db.prepare('UPDATE channels SET active = 0, updated_at = ? WHERE sync_seq < ? AND active = 1').bind(nowSec, seq));
    stmts.push(
      db.prepare(
        `UPDATE channels SET xtream_id = 100000 + rowid WHERE xtream_id IS NULL`,
      ),
    );
    for (let i = 0; i < stmts.length; i += 50) await db.batch(stmts.slice(i, i + 50));

    await db.batch([
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'playlist_hash'`).bind(hash),
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'last_sync'`).bind(String(nowSec)),
      db.prepare(`UPDATE settings SET value = 'ok' WHERE key = 'sync_status'`),
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'channel_count'`).bind(String(parsed.channels.length)),
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'category_count'`).bind(String(parsed.categories.length)),
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'sync_seq'`).bind(String(seq)),
      db.prepare(`UPDATE settings SET value = ? WHERE key = 'playlist_source'`).bind(env.PLAYLIST_URL),
    ]);
    await logSync(db, startedAt, 'ok', trigger, parsed.channels.length, parsed.categories.length, hash, '');
    return { status: 'ok', channelCount: parsed.channels.length, categoryCount: parsed.categories.length, hash };
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'db error';
    await failSync(db, startedAt, trigger, msg);
    return { status: 'failed', error: msg };
  }
}

async function failSync(db: D1Database, startedAt: number, trigger: string, error: string): Promise<void> {
  // Keep the previous playlist live; only record the failure.
  await setSetting(db, 'sync_status', 'failed');
  await logSync(db, startedAt, 'failed', trigger, 0, 0, '', error);
}

async function logSync(
  db: D1Database,
  startedAt: number,
  status: string,
  trigger: string,
  channels: number,
  categories: number,
  hash: string,
  error: string,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO sync_logs (started_at, finished_at, status, trigger_by, channel_count, category_count, playlist_hash, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(startedAt, Math.floor(Date.now() / 1000), status, trigger, channels, categories, hash, error)
    .run();
}
