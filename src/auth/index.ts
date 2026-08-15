import type { Env, UserRow, AccessKeyRow } from '../types';
import { hashPassword, hashAccessKey, timingSafeEqual } from '../utils/crypto';
import { normalizeMac } from '../utils/mac';
import { ErrorCodes, type ErrorCode } from '../errors/codes';

const now = () => Math.floor(Date.now() / 1000);

export type AuthResult<T> = { ok: true; value: T } | { ok: false; code: ErrorCode; status: number };

function checkStatusAndExpiry(status: string, expiresAt: number | null): { code: ErrorCode; status: number } | null {
  if (status === 'disabled' || status === 'revoked') return { code: ErrorCodes.AUTH_DISABLED, status: 403 };
  if (status === 'expired') return { code: ErrorCodes.AUTH_EXPIRED, status: 403 };
  if (status !== 'active') return { code: ErrorCodes.AUTH_INVALID, status: 403 };
  if (expiresAt !== null && expiresAt > 0 && expiresAt <= now()) return { code: ErrorCodes.AUTH_EXPIRED, status: 403 };
  return null;
}

/** Xtream-style username/password authentication. */
export async function authenticateUser(env: Env, username: string, password: string): Promise<AuthResult<UserRow>> {
  if (!username || !password || username.length > 128 || password.length > 256) {
    return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };
  }
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first<UserRow>();
  if (!user) {
    // Burn comparable time to reduce user-enumeration signal.
    await hashPassword(env.SECRET_KEY, 'no-such-user', password);
    return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };
  }
  const hash = await hashPassword(env.SECRET_KEY, user.password_salt, password);
  if (!timingSafeEqual(hash, user.password_hash)) return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };
  const bad = checkStatusAndExpiry(user.status, user.expires_at);
  if (bad) return { ok: false, ...bad };
  return { ok: true, value: user };
}

/**
 * Access-key authentication with optional MAC-based device registration.
 * The MAC is client-declared, so it is treated as a device *label* + soft
 * device-count limiter, never as a standalone security factor — the access
 * key itself is the credential.
 */
export async function authenticateAccessKey(
  env: Env,
  rawKey: string,
  rawMac: string | null,
  userAgent: string,
): Promise<AuthResult<AccessKeyRow>> {
  if (!rawKey || rawKey.length < 8 || rawKey.length > 128) {
    return { ok: false, code: ErrorCodes.KEY_INVALID, status: 401 };
  }
  const keyHash = await hashAccessKey(env.SECRET_KEY, rawKey);
  const key = await env.DB.prepare('SELECT * FROM access_keys WHERE key_hash = ?').bind(keyHash).first<AccessKeyRow>();
  if (!key) return { ok: false, code: ErrorCodes.KEY_INVALID, status: 401 };
  const bad = checkStatusAndExpiry(key.status, key.expires_at);
  if (bad) {
    return { ok: false, code: bad.code === ErrorCodes.AUTH_EXPIRED ? ErrorCodes.KEY_EXPIRED : bad.code, status: bad.status };
  }

  const mac = normalizeMac(rawMac);
  if (mac) {
    const ts = now();
    const device = await env.DB.prepare('SELECT id, status FROM devices WHERE access_key_id = ? AND mac_address = ?')
      .bind(key.id, mac)
      .first<{ id: number; status: string }>();
    if (device) {
      if (device.status !== 'active') return { ok: false, code: ErrorCodes.AUTH_DISABLED, status: 403 };
      await env.DB.prepare('UPDATE devices SET last_seen = ?, user_agent = ? WHERE id = ?')
        .bind(ts, userAgent.slice(0, 256), device.id)
        .run();
    } else {
      const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM devices WHERE access_key_id = ? AND status = 'active'")
        .bind(key.id)
        .first<{ n: number }>();
      if ((cnt?.n ?? 0) >= key.max_devices) return { ok: false, code: ErrorCodes.DEVICE_LIMIT, status: 403 };
      await env.DB.prepare(
        'INSERT INTO devices (access_key_id, mac_address, user_agent, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)',
      )
        .bind(key.id, mac, userAgent.slice(0, 256), 'active', ts, ts)
        .run();
    }
  }
  return { ok: true, value: key };
}

/** Admin bearer-token authentication. Admin API is disabled when ADMIN_TOKEN is unset. */
export function authenticateAdmin(env: Env, req: Request): AuthResult<true> {
  const configured = env.ADMIN_TOKEN;
  if (!configured || configured.length < 16) return { ok: false, code: ErrorCodes.ADMIN_DISABLED, status: 404 };
  const header = req.headers.get('Authorization') ?? '';
  const m = header.match(/^Bearer\s+(.+)$/);
  if (!m || !m[1] || !timingSafeEqual(m[1], configured)) {
    return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };
  }
  return { ok: true, value: true };
}
