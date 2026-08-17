import type { Env } from '../types';
import type { TokenPayload } from '../token';

interface SessionAuthorizationRow {
  session_user_id: number;
  session_status: string;
  session_expires_at: number | null;
  user_status: string;
  user_expires_at: number | null;
}

interface AccessKeyAuthorizationRow {
  user_id: number | null;
  status: string;
  expires_at: number | null;
}

interface UserAuthorizationRow {
  status: string;
  expires_at: number | null;
}

function isActive(status: string, expiresAt: number | null, now: number): boolean {
  return status === 'active' && (expiresAt === null || expiresAt <= 0 || expiresAt > now);
}

/**
 * Re-check the revocable identities carried by a verified manifest/EPG token.
 *
 * Segment tokens are deliberately short lived and can only be minted after a
 * manifest passes this check. Avoiding a D1 read for every media chunk keeps
 * playback practical while session/account/key revocation stops the next
 * manifest refresh immediately. Previously issued chunks expire within an hour
 * and never later than their parent manifest capability.
 */
export async function isTokenAuthorizationActive(env: Env, payload: TokenPayload): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);

  if (payload.sid !== undefined) {
    if (payload.uid === undefined) return false;
    const row = await env.DB.prepare(
      `SELECT s.user_id AS session_user_id,
              s.status AS session_status,
              s.expires_at AS session_expires_at,
              u.status AS user_status,
              u.expires_at AS user_expires_at
         FROM user_sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.id = ?`,
    )
      .bind(payload.sid)
      .first<SessionAuthorizationRow>();
    if (!row || row.session_user_id !== payload.uid) return false;
    return (
      isActive(row.session_status, row.session_expires_at, now) &&
      isActive(row.user_status, row.user_expires_at, now)
    );
  }

  if (payload.aid !== undefined) {
    const key = await env.DB.prepare('SELECT user_id, status, expires_at FROM access_keys WHERE id = ?')
      .bind(payload.aid)
      .first<AccessKeyAuthorizationRow>();
    if (!key || !isActive(key.status, key.expires_at, now)) return false;
    // Linking or re-linking a key invalidates tokens minted under its previous
    // ownership rather than allowing an old capability to cross accounts.
    if ((key.user_id ?? undefined) !== payload.uid) return false;
  }

  if (payload.uid !== undefined) {
    const user = await env.DB.prepare('SELECT status, expires_at FROM users WHERE id = ?')
      .bind(payload.uid)
      .first<UserAuthorizationRow>();
    if (!user || !isActive(user.status, user.expires_at, now)) return false;
  }

  return true;
}
