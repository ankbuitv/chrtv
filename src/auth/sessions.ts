import type { Env, UserRow } from '../types';
import type { AuthResult } from './index';
import { ErrorCodes } from '../errors/codes';
import { hmacHex, randomHex } from '../utils/crypto';
import { getClientIp } from '../token';

const SESSION_TOKEN_RE = /^[a-f0-9]{64}$/;
const now = () => Math.floor(Date.now() / 1000);

export interface UserSessionRow {
  id: number;
  user_id: number;
  token_prefix: string;
  device_name: string;
  user_agent: string;
  ip_address: string;
  last_ip: string;
  status: string;
  created_at: number;
  last_seen: number;
  expires_at: number | null;
}

export interface AuthenticatedSession {
  session: UserSessionRow;
  user: UserRow;
}

async function sessionHash(secret: string, token: string): Promise<string> {
  return hmacHex(secret, `session|${token}`);
}

function bearerToken(req: Request): string {
  const match = (req.headers.get('Authorization') ?? '').match(/^Bearer\s+([a-f0-9]{64})$/i);
  return match?.[1]?.toLowerCase() ?? '';
}

/** Create a revocable playlist bearer session, atomically respecting max_connections. */
export async function createUserSession(
  req: Request,
  env: Env,
  user: UserRow,
  deviceName: string,
): Promise<{ ok: true; token: string; session: UserSessionRow } | { ok: false }> {
  const token = randomHex(32);
  const hash = await sessionHash(env.SECRET_KEY, token);
  const ts = now();
  const ip = getClientIp(req) ?? '';
  const maxSessions = Math.max(1, Math.min(100, Math.floor(user.max_connections || 1)));
  const result = await env.DB.prepare(
    `INSERT INTO user_sessions
       (user_id, token_hash, token_prefix, device_name, user_agent, ip_address, last_ip, status, created_at, last_seen, expires_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?
      WHERE (SELECT COUNT(*) FROM user_sessions
              WHERE user_id = ? AND status = 'active' AND (expires_at IS NULL OR expires_at > ?)) < ?`,
  )
    .bind(
      user.id,
      hash,
      token.slice(0, 12),
      deviceName.trim().slice(0, 80),
      (req.headers.get('user-agent') ?? '').slice(0, 256),
      ip,
      ip,
      ts,
      ts,
      user.expires_at,
      user.id,
      ts,
      maxSessions,
    )
    .run();

  if ((result.meta.changes ?? 0) < 1) return { ok: false };
  const session = await env.DB.prepare(
    `SELECT id, user_id, token_prefix, device_name, user_agent, ip_address, last_ip, status, created_at, last_seen, expires_at
       FROM user_sessions WHERE token_hash = ?`,
  )
    .bind(hash)
    .first<UserSessionRow>();
  if (!session) return { ok: false };
  return { ok: true, token, session };
}

export async function authenticateSessionToken(
  req: Request,
  env: Env,
  suppliedToken?: string,
  touch = false,
): Promise<AuthResult<AuthenticatedSession>> {
  const token = (suppliedToken ?? bearerToken(req)).toLowerCase();
  if (!SESSION_TOKEN_RE.test(token)) return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };
  const hash = await sessionHash(env.SECRET_KEY, token);
  const row = await env.DB.prepare(
    `SELECT s.id, s.user_id, s.token_prefix, s.device_name, s.user_agent, s.ip_address, s.last_ip,
            s.status, s.created_at, s.last_seen, s.expires_at,
            u.username, u.password_hash, u.password_salt, u.status AS user_status,
            u.max_connections, u.expires_at AS user_expires_at, u.created_at AS user_created_at, u.updated_at
       FROM user_sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
  )
    .bind(hash)
    .first<
      UserSessionRow & {
        username: string;
        password_hash: string;
        password_salt: string;
        user_status: string;
        max_connections: number;
        user_expires_at: number | null;
        user_created_at: number;
        updated_at: number;
      }
    >();
  if (!row) return { ok: false, code: ErrorCodes.AUTH_INVALID, status: 401 };

  const ts = now();
  if (row.status !== 'active') return { ok: false, code: ErrorCodes.AUTH_DISABLED, status: 403 };
  if (row.expires_at !== null && row.expires_at > 0 && row.expires_at <= ts) {
    await env.DB.prepare("UPDATE user_sessions SET status = 'expired' WHERE id = ?").bind(row.id).run();
    return { ok: false, code: ErrorCodes.AUTH_EXPIRED, status: 403 };
  }
  if (row.user_status !== 'active') {
    return {
      ok: false,
      code: row.user_status === 'expired' ? ErrorCodes.AUTH_EXPIRED : ErrorCodes.AUTH_DISABLED,
      status: 403,
    };
  }
  if (row.user_expires_at !== null && row.user_expires_at > 0 && row.user_expires_at <= ts) {
    return { ok: false, code: ErrorCodes.AUTH_EXPIRED, status: 403 };
  }

  const session: UserSessionRow = {
    id: row.id,
    user_id: row.user_id,
    token_prefix: row.token_prefix,
    device_name: row.device_name,
    user_agent: row.user_agent,
    ip_address: row.ip_address,
    last_ip: row.last_ip,
    status: row.status,
    created_at: row.created_at,
    last_seen: row.last_seen,
    expires_at: row.expires_at,
  };
  const user: UserRow = {
    id: row.user_id,
    username: row.username,
    password_hash: row.password_hash,
    password_salt: row.password_salt,
    status: row.user_status,
    max_connections: row.max_connections,
    expires_at: row.user_expires_at,
    created_at: row.user_created_at,
    updated_at: row.updated_at,
  };

  if (touch) {
    const ip = getClientIp(req) ?? '';
    await env.DB.prepare('UPDATE user_sessions SET last_seen = ?, last_ip = ?, user_agent = ? WHERE id = ?')
      .bind(ts, ip, (req.headers.get('user-agent') ?? '').slice(0, 256), row.id)
      .run();
    session.last_seen = ts;
    session.last_ip = ip;
  }
  return { ok: true, value: { session, user } };
}

export async function listUserSessions(env: Env, userId: number): Promise<UserSessionRow[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, user_id, token_prefix, device_name, user_agent, ip_address, last_ip, status, created_at, last_seen, expires_at
       FROM user_sessions WHERE user_id = ? ORDER BY last_seen DESC LIMIT 100`,
  )
    .bind(userId)
    .all<UserSessionRow>();
  return results;
}

export async function revokeUserSession(env: Env, userId: number, sessionId: number): Promise<boolean> {
  const result = await env.DB.prepare("UPDATE user_sessions SET status = 'revoked' WHERE id = ? AND user_id = ?")
    .bind(sessionId, userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}
