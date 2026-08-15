import type { Env } from '../types';
import { authenticateAdmin } from '../auth';
import { syncPlaylist } from '../playlist/sync';
import { getSettings } from '../db/settings';
import { hashPassword, hashAccessKey, randomHex } from '../utils/crypto';
import { normalizeMac } from '../utils/mac';
import { clearFailure } from '../proxy/failureCache';
import { healthCheckBatch, listOfflineChannels, healthStats, DEFAULT_HEALTH_BATCH } from '../playlist/health';
import { jsonResponse, errorResponse, methodNotAllowed, logEvent } from '../utils/http';
import { ErrorCodes } from '../errors/codes';

/**
 * Admin API — /api/admin/*
 * Bearer-token authenticated (ADMIN_TOKEN secret). Returns 404 when the admin
 * token is not configured, so the surface is invisible unless enabled.
 * Never returns password hashes, key hashes, or SECRET_KEY.
 */

const VALID_STATUSES = new Set(['active', 'disabled', 'expired', 'revoked']);
const now = () => Math.floor(Date.now() / 1000);

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = (await req.json()) as unknown;
    return typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function str(v: unknown, max = 256): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

export async function handleAdmin(req: Request, env: Env, requestId: string, subPath: string): Promise<Response> {
  const auth = authenticateAdmin(env, req);
  if (!auth.ok) {
    if (auth.code !== ErrorCodes.ADMIN_DISABLED) logEvent(requestId, '/api/admin', auth.code);
    return errorResponse(auth.code, auth.status, requestId);
  }

  const method = req.method;
  const db = env.DB;

  try {
    // ---- status & stats ----
    if (subPath === 'status' && method === 'GET') {
      const settings = await getSettings(db, [
        'last_sync',
        'sync_status',
        'channel_count',
        'category_count',
        'playlist_hash',
        'playlist_source',
      ]);
      const [users, keys, devices, health] = await Promise.all([
        db.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>(),
        db.prepare('SELECT COUNT(*) AS n FROM access_keys').first<{ n: number }>(),
        db.prepare('SELECT COUNT(*) AS n FROM devices').first<{ n: number }>(),
        healthStats(db),
      ]);
      return jsonResponse({
        service: 'CHRTV',
        playlist: settings,
        health,
        stats: { users: users?.n ?? 0, access_keys: keys?.n ?? 0, devices: devices?.n ?? 0 },
      });
    }

    // ---- channels / categories ----
    if (subPath === 'channels' && method === 'GET') {
      const { results } = await db
        .prepare(
          `SELECT c.id, c.xtream_id, c.name, c.tvg_id, c.tvg_logo, c.position, c.active, cat.name AS category,
                  h.status AS health_status, h.error_code, h.http_status, h.checked_at AS last_checked
             FROM channels c
             LEFT JOIN categories cat ON cat.id = c.category_id
             LEFT JOIN channel_health h ON h.channel_id = c.id
            ORDER BY c.position ASC LIMIT 5000`,
        )
        .all();
      return jsonResponse(results);
    }
    if (subPath === 'categories' && method === 'GET') {
      const { results } = await db.prepare('SELECT id, name, position FROM categories ORDER BY position ASC').all();
      return jsonResponse(results);
    }

    // ---- sync ----
    if (subPath === 'sync') {
      if (method !== 'POST') return methodNotAllowed(['POST'], requestId);
      const result = await syncPlaylist(env, 'admin');
      return jsonResponse(result, result.status === 'failed' ? 502 : result.status === 'busy' ? 409 : 200);
    }
    if (subPath === 'sync-logs' && method === 'GET') {
      const { results } = await db.prepare('SELECT * FROM sync_logs ORDER BY id DESC LIMIT 50').all();
      return jsonResponse(results);
    }

    // ---- failures ----
    if (subPath === 'failures' && method === 'GET') {
      const { results } = await db
        .prepare(
          `SELECT f.channel_id, c.name, f.error_code, f.http_status, f.created_at
           FROM stream_failures f LEFT JOIN channels c ON c.id = f.channel_id
           ORDER BY f.id DESC LIMIT 200`,
        )
        .all();
      return jsonResponse(results);
    }
    if (subPath.startsWith('failures/') && method === 'DELETE') {
      const channelId = subPath.slice('failures/'.length);
      if (!/^[a-f0-9]{16}$/.test(channelId)) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
      await clearFailure(channelId);
      await db.prepare('DELETE FROM stream_failures WHERE channel_id = ?').bind(channelId).run();
      return jsonResponse({ ok: true });
    }

    // ---- channel health (proactive offline detection) ----
    if (subPath === 'offline' && method === 'GET') {
      const offline = await listOfflineChannels(db, 1000);
      return jsonResponse({ count: offline.length, channels: offline });
    }
    if (subPath === 'health-check') {
      if (method !== 'POST') return methodNotAllowed(['POST'], requestId);
      // On demand an operator may sweep more channels at once (?limit=), but
      // the module caps it at MAX_PROBES_PER_RUN (12): each probe can take up
      // to 1+3 redirect fetches, and the Free plan allows only 50 subrequests
      // per invocation. Past the cap, fetches start failing with a network
      // error and every channel they touch gets falsely flagged offline.
      // Call the endpoint repeatedly to sweep the whole list.
      const requested = Number(new URL(req.url).searchParams.get('limit'));
      const limit = Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_HEALTH_BATCH;
      const summary = await healthCheckBatch(env, limit);
      logEvent(requestId, '/api/admin/health-check', 'HEALTH_CHECK', JSON.stringify(summary));
      return jsonResponse(summary);
    }

    // ---- users ----
    if (subPath === 'users') {
      if (method === 'GET') {
        const { results } = await db
          .prepare('SELECT id, username, status, max_connections, expires_at, created_at, updated_at FROM users ORDER BY id')
          .all();
        return jsonResponse(results); // hashes intentionally excluded
      }
      if (method === 'POST') {
        const body = await readJson(req);
        const username = str(body?.['username'], 128).trim();
        const password = str(body?.['password'], 256);
        if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username) || password.length < 8) {
          return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
        }
        const salt = randomHex(16);
        const hash = await hashPassword(env.SECRET_KEY, salt, password);
        const expiresAt = typeof body?.['expires_at'] === 'number' ? (body['expires_at'] as number) : null;
        const ts = now();
        try {
          await db
            .prepare(
              `INSERT INTO users (username, password_hash, password_salt, status, max_connections, expires_at, created_at, updated_at)
               VALUES (?, ?, ?, 'active', ?, ?, ?, ?)`,
            )
            .bind(username, hash, salt, Number(body?.['max_connections']) || 1, expiresAt, ts, ts)
            .run();
        } catch {
          return errorResponse(ErrorCodes.BAD_REQUEST, 409, requestId);
        }
        return jsonResponse({ ok: true, username }, 201);
      }
      return methodNotAllowed(['GET', 'POST'], requestId);
    }
    const userMatch = subPath.match(/^users\/(\d+)$/);
    if (userMatch) {
      const id = Number(userMatch[1]);
      if (method === 'PATCH') {
        const body = await readJson(req);
        const status = str(body?.['status'], 16);
        if (status && !VALID_STATUSES.has(status)) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
        if (status) await db.prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').bind(status, now(), id).run();
        if (typeof body?.['expires_at'] === 'number' || body?.['expires_at'] === null) {
          await db
            .prepare('UPDATE users SET expires_at = ?, updated_at = ? WHERE id = ?')
            .bind(body['expires_at'] as number | null, now(), id)
            .run();
        }
        return jsonResponse({ ok: true });
      }
      if (method === 'DELETE') {
        await db.prepare("UPDATE users SET status = 'revoked', updated_at = ? WHERE id = ?").bind(now(), id).run();
        return jsonResponse({ ok: true });
      }
      return methodNotAllowed(['PATCH', 'DELETE'], requestId);
    }

    // ---- access keys ----
    if (subPath === 'keys') {
      if (method === 'GET') {
        const { results } = await db
          .prepare(
            'SELECT id, key_prefix, label, username, status, max_devices, expires_at, created_at FROM access_keys ORDER BY id',
          )
          .all();
        return jsonResponse(results); // key hashes intentionally excluded
      }
      if (method === 'POST') {
        const body = await readJson(req);
        const rawKey = `chr_${randomHex(24)}`;
        const keyHash = await hashAccessKey(env.SECRET_KEY, rawKey);
        const expiresAt = typeof body?.['expires_at'] === 'number' ? (body['expires_at'] as number) : null;
        const ts = now();
        await db
          .prepare(
            `INSERT INTO access_keys (key_hash, key_prefix, label, username, status, max_devices, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
          )
          .bind(
            keyHash,
            rawKey.slice(0, 12),
            str(body?.['label']),
            str(body?.['username'], 128),
            Number(body?.['max_devices']) || 3,
            expiresAt,
            ts,
            ts,
          )
          .run();
        // The raw key is returned exactly once, at creation.
        return jsonResponse({ ok: true, access_key: rawKey }, 201);
      }
      return methodNotAllowed(['GET', 'POST'], requestId);
    }
    const keyMatch = subPath.match(/^keys\/(\d+)$/);
    if (keyMatch) {
      const id = Number(keyMatch[1]);
      if (method === 'PATCH') {
        const body = await readJson(req);
        const status = str(body?.['status'], 16);
        if (!VALID_STATUSES.has(status)) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
        await db.prepare('UPDATE access_keys SET status = ?, updated_at = ? WHERE id = ?').bind(status, now(), id).run();
        return jsonResponse({ ok: true });
      }
      if (method === 'DELETE') {
        await db.prepare("UPDATE access_keys SET status = 'revoked', updated_at = ? WHERE id = ?").bind(now(), id).run();
        return jsonResponse({ ok: true });
      }
      return methodNotAllowed(['PATCH', 'DELETE'], requestId);
    }

    // ---- devices ----
    if (subPath === 'devices' && method === 'GET') {
      const { results } = await db
        .prepare(
          `SELECT d.id, d.access_key_id, k.key_prefix, d.mac_address, d.status, d.first_seen, d.last_seen
           FROM devices d JOIN access_keys k ON k.id = d.access_key_id ORDER BY d.last_seen DESC LIMIT 500`,
        )
        .all();
      return jsonResponse(results);
    }
    const devMatch = subPath.match(/^devices\/(\d+)$/);
    if (devMatch) {
      const id = Number(devMatch[1]);
      if (method === 'PATCH') {
        const body = await readJson(req);
        const status = str(body?.['status'], 16);
        if (!['active', 'disabled', 'revoked'].includes(status)) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
        await db.prepare('UPDATE devices SET status = ? WHERE id = ?').bind(status, id).run();
        return jsonResponse({ ok: true });
      }
      if (method === 'DELETE') {
        await db.prepare('DELETE FROM devices WHERE id = ?').bind(id).run();
        return jsonResponse({ ok: true });
      }
      return methodNotAllowed(['PATCH', 'DELETE'], requestId);
    }

    // Lookup a device by MAC (normalized)
    if (subPath.startsWith('devices/mac/') && method === 'GET') {
      const mac = normalizeMac(subPath.slice('devices/mac/'.length));
      if (!mac) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
      const { results } = await db
        .prepare('SELECT id, access_key_id, mac_address, status, first_seen, last_seen FROM devices WHERE mac_address = ?')
        .bind(mac)
        .all();
      return jsonResponse(results);
    }

    return errorResponse(ErrorCodes.NOT_FOUND, 404, requestId);
  } catch (err) {
    logEvent(requestId, `/api/admin/${subPath}`, ErrorCodes.DB_ERROR, err instanceof Error ? err.message : 'unknown');
    return errorResponse(ErrorCodes.DB_ERROR, 500, requestId);
  }
}
