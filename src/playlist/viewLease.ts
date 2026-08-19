import type { Env } from '../types';
import { getClientIp, tokenBindingSeed, type TokenBinding, type TokenPayload } from '../token';
import { hmacHex, randomHex } from '../utils/crypto';

/** IPTV clients have no reliable "stop" event. Manifest silence is the lease boundary. */
export const VIEWER_LEASE_IDLE_SECONDS = 60;

interface ViewerLeaseRow {
  identity_hash: string;
  lease_id: string;
  issued_at: number;
  activated_at: number | null;
  last_seen: number;
  updated_at: number;
}

function newLeaseId(): string {
  return randomHex(16);
}

/**
 * Build a private, stable viewer identity. The observed IP participates in list
 * separation but is deliberately not an enforcement claim: a CGNAT/IP change
 * can obtain a new list without cutting an already playing stream. uid/sid,
 * MAC and access-key claims remain encrypted in the stream token itself.
 */
async function viewerIdentityHash(req: Request, env: Env, binding: TokenBinding): Promise<string> {
  const ip = getClientIp(req) ?? '';
  const ua = (req.headers.get('user-agent') ?? '').trim().slice(0, 256);
  return hmacHex(env.SECRET_KEY, `viewer|${tokenBindingSeed(binding)}|${ip}|${ua}`);
}

function leaseUnavailable(err: unknown): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: 'VIEWER_LEASE_UNAVAILABLE',
      error: err instanceof Error ? err.message : 'unknown',
    }),
  );
}

/**
 * Return the current list generation, rotating it only after playback is idle.
 * Returns undefined when lease bookkeeping is unavailable (missing migration /
 * D1 error): the playlist then falls back to legacy non-lease tokens, so a
 * bookkeeping failure can never take the playlist down.
 */
export async function getViewerLease(
  req: Request,
  env: Env,
  binding: TokenBinding,
): Promise<{ id: string; issuedAt: number } | undefined> {
  try {
    const identityHash = await viewerIdentityHash(req, env, binding);
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - VIEWER_LEASE_IDLE_SECONDS;

    let row = await env.DB.prepare(
      'SELECT identity_hash, lease_id, issued_at, activated_at, last_seen, updated_at FROM viewer_leases WHERE identity_hash = ?',
    )
      .bind(identityHash)
      .first<ViewerLeaseRow>();

    if (!row) {
      const leaseId = newLeaseId();
      await env.DB.prepare(
        `INSERT OR IGNORE INTO viewer_leases
           (identity_hash, lease_id, issued_at, activated_at, last_seen, updated_at)
         VALUES (?, ?, ?, NULL, 0, ?)`,
      )
        .bind(identityHash, leaseId, now, now)
        .run();
      row = await env.DB.prepare(
        'SELECT identity_hash, lease_id, issued_at, activated_at, last_seen, updated_at FROM viewer_leases WHERE identity_hash = ?',
      )
        .bind(identityHash)
        .first<ViewerLeaseRow>();
      if (!row) throw new Error('viewer lease creation failed');
      return { id: row.lease_id, issuedAt: row.issued_at };
    }

    // An active player refreshes a media/child manifest every few seconds. Keep
    // the complete channel list byte-stable while that heartbeat is present.
    const active = row.activated_at !== null && row.last_seen >= cutoff;
    // Avoid invalidating a list between an IPTV app's probe and actual playback.
    const freshlyIssued = row.activated_at === null && row.updated_at >= cutoff;
    if (active || freshlyIssued) return { id: row.lease_id, issuedAt: row.issued_at };

    const replacement = newLeaseId();
    await env.DB.prepare(
      `UPDATE viewer_leases
          SET lease_id = ?, issued_at = ?, activated_at = NULL, last_seen = 0, updated_at = ?
        WHERE identity_hash = ? AND lease_id = ?`,
    )
      .bind(replacement, now, now, identityHash, row.lease_id)
      .run();

    const current = await env.DB.prepare('SELECT lease_id, issued_at FROM viewer_leases WHERE identity_hash = ?')
      .bind(identityHash)
      .first<{ lease_id: string; issued_at: number }>();
    if (!current) throw new Error('viewer lease rotation failed');
    return { id: current.lease_id, issuedAt: current.issued_at };
  } catch (err) {
    leaseUnavailable(err);
    return undefined;
  }
}

/**
 * Validate and heartbeat a tokenized channel generation. A first request
 * activates it. A player returning after 60+ seconds of manifest silence
 * (pause, seek, network stall) REVIVES the same generation instead of having
 * it rotated away under it — only a generation that a later playlist fetch
 * already rotated (getViewerLease) is rejected with 410, so copied URLs from
 * an abandoned list still stop working without ever killing a legitimate
 * resume. Fails open on D1 errors: lease freshness is hygiene, not
 * authorization — the token itself, its binding claims, and the identity
 * recheck already gate the request.
 */
export async function touchViewerLease(env: Env, payload: TokenPayload): Promise<boolean> {
  if (!payload.l) return true; // Backward compatibility for non-playlist/old tokens.
  const now = Math.floor(Date.now() / 1000);
  const cutoff = now - VIEWER_LEASE_IDLE_SECONDS;
  try {
    const row = await env.DB.prepare(
      'SELECT identity_hash, lease_id, issued_at, activated_at, last_seen, updated_at FROM viewer_leases WHERE lease_id = ?',
    )
      .bind(payload.l)
      .first<ViewerLeaseRow>();
    if (!row || row.lease_id !== payload.l) return false;

    if (row.activated_at !== null && row.last_seen < cutoff) {
      // Returning viewer: refresh the heartbeat in place. Rotation is reserved
      // for getViewerLease, i.e. for a playlist re-fetch after idle.
      await env.DB.prepare(
        `UPDATE viewer_leases
            SET last_seen = ?, updated_at = ?
          WHERE identity_hash = ? AND lease_id = ?`,
      )
        .bind(now, now, row.identity_hash, payload.l)
        .run();
      return true;
    }

    // Live manifests can refresh every 1–5 seconds. One durable heartbeat per
    // 15 seconds is enough for a 60-second lease and avoids a D1 write per poll.
    if (row.activated_at !== null && row.last_seen >= now - 15) return true;

    await env.DB.prepare(
      `UPDATE viewer_leases
          SET activated_at = COALESCE(activated_at, ?), last_seen = ?, updated_at = ?
        WHERE identity_hash = ? AND lease_id = ?`,
    )
      .bind(now, now, now, row.identity_hash, payload.l)
      .run();
    return true;
  } catch (err) {
    leaseUnavailable(err);
    return true;
  }
}
