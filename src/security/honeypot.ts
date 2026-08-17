import type { Env } from '../types';
import { hmacHex } from '../utils/crypto';
import { getClientIp } from '../token';

/**
 * Deliberately fake targets that real IPTV clients and CHRTV operators never
 * need. Keep this list conservative: do NOT trap generic `/admin`, Xtream, or
 * Stalker paths because legitimate IPTV applications probe those routes.
 */
const EXACT_TRAPS = new Set([
  '/.ds_store',
  '/.git',
  '/.svn',
  '/.hg',
  '/.aws',
  '/.ssh',
  '/wp-login.php',
  '/wp-admin',
  '/xmlrpc.php',
  '/adminer.php',
  '/phpmyadmin',
  '/pma',
  '/cgi-bin',
  '/actuator',
  '/server-status',
  '/phpinfo.php',
  '/config.php',
]);

const PREFIX_TRAPS = [
  '/.env',
  '/.git/',
  '/.svn/',
  '/.hg/',
  '/.aws/',
  '/.ssh/',
  '/wp-admin/',
  '/wp-content/',
  '/phpmyadmin/',
  '/pma/',
  '/vendor/phpunit/',
  '/cgi-bin/',
  '/actuator/',
  '/debug/default/',
];

export const DEFAULT_BAN_SECONDS = 24 * 60 * 60;
const MAX_BAN_SECONDS = 7 * 24 * 60 * 60;
// Brief negatives limit D1 reads without allowing a new cross-colo ban to be
// hidden behind stale edge state for more than a few seconds.
const NEGATIVE_CACHE_SECONDS = 30;
// Keep positive cache brief so an admin unban propagates across colos quickly.
const POSITIVE_CACHE_SECONDS = 60;
export const LOGIN_FAILURE_LIMIT = 5;
const LOGIN_FAILURE_WINDOW_SECONDS = 10 * 60;

interface LoginFailureState {
  count: number;
  startedAt: number;
}

function normalizedPath(pathname: string): string {
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // A malformed escape is not a recognized trap and will become a normal 404.
  }
  return decoded.replace(/\/{2,}/g, '/').toLowerCase();
}

export function isHoneypotPath(pathname: string): boolean {
  const path = normalizedPath(pathname);
  if (EXACT_TRAPS.has(path)) return true;
  return PREFIX_TRAPS.some((prefix) => path.startsWith(prefix));
}

export function honeypotEnabled(env: Env): boolean {
  return (env.HONEYPOT_ENABLED ?? 'true').toLowerCase() !== 'false';
}

/**
 * Prevent cross-site images/iframes from turning a trap URL into a way to ban
 * innocent browser visitors. The response remains the same fake 404; only the
 * side effect is suppressed for browser-declared cross-site requests.
 */
export function shouldBanHoneypotRequest(req: Request): boolean {
  return (req.headers.get('Sec-Fetch-Site') ?? '').trim().toLowerCase() !== 'cross-site';
}

export function securityBanSeconds(env: Env): number {
  const configured = Number(env.HONEYPOT_BAN_SECONDS);
  if (!Number.isFinite(configured) || configured < 60) return DEFAULT_BAN_SECONDS;
  return Math.min(Math.floor(configured), MAX_BAN_SECONDS);
}

async function ipHash(secret: string, ip: string): Promise<string> {
  return hmacHex(secret, `security-ban|${ip}`);
}

function banCacheKey(hash: string): Request {
  return new Request(`https://chrtv.internal/security/ban/${hash}`);
}

function loginFailureCacheKey(hash: string): Request {
  return new Request(`https://chrtv.internal/security/login-failures/${hash}`);
}

async function cacheBan(hash: string, banned: boolean, ttl: number): Promise<void> {
  try {
    await caches.default.put(
      banCacheKey(hash),
      new Response(null, {
        headers: {
          'Cache-Control': `public, max-age=${Math.max(1, ttl)}`,
          'X-CHRTV-Banned': banned ? '1' : '0',
        },
      }),
    );
  } catch {
    // D1 remains the source of truth when the edge cache is unavailable.
  }
}

async function cachedBan(hash: string): Promise<boolean | null> {
  try {
    const hit = await caches.default.match(banCacheKey(hash));
    if (!hit) return null;
    return hit.headers.get('X-CHRTV-Banned') === '1';
  } catch {
    return null;
  }
}

/** Check a privacy-preserving D1 ban, with positive and negative edge caching. */
export async function isClientBanned(req: Request, env: Env): Promise<boolean> {
  const ip = getClientIp(req);
  if (!ip) return false;
  const hash = await ipHash(env.SECRET_KEY, ip);
  const cached = await cachedBan(hash);
  if (cached !== null) return cached;

  const now = Math.floor(Date.now() / 1000);
  try {
    const row = await env.DB.prepare('SELECT expires_at FROM security_bans WHERE ip_hash = ? AND expires_at > ?')
      .bind(hash, now)
      .first<{ expires_at: number }>();
    if (!row) {
      await cacheBan(hash, false, NEGATIVE_CACHE_SECONDS);
      return false;
    }
    await cacheBan(hash, true, Math.min(row.expires_at - now, POSITIVE_CACHE_SECONDS));
    return true;
  } catch {
    // Security storage failure must not take the streaming service offline.
    return false;
  }
}

/** Ban the Cloudflare-observed IP without ever persisting the raw address. */
export async function banClient(req: Request, env: Env, reason: string): Promise<boolean> {
  const ip = getClientIp(req);
  if (!ip) return false;
  const hash = await ipHash(env.SECRET_KEY, ip);
  const now = Math.floor(Date.now() / 1000);
  const ttl = securityBanSeconds(env);
  const expiresAt = now + ttl;

  // Update the hot edge state first so the very next request is blocked even if
  // durable audit storage is temporarily unavailable.
  await cacheBan(hash, true, Math.min(ttl, POSITIVE_CACHE_SECONDS));
  try {
    await env.DB.prepare(
      `INSERT INTO security_bans (ip_hash, reason, first_seen, last_seen, expires_at, hit_count)
       VALUES (?, ?, ?, ?, ?, 1)
       ON CONFLICT(ip_hash) DO UPDATE SET
         reason = excluded.reason,
         last_seen = excluded.last_seen,
         expires_at = MAX(security_bans.expires_at, excluded.expires_at),
         hit_count = security_bans.hit_count + 1`,
    )
      .bind(hash, reason.slice(0, 128), now, now, expiresAt)
      .run();
  } catch {
    // The edge ban is still useful; do not turn a trap request into a 500.
  }
  return true;
}

export async function clearBanByHash(db: D1Database, hash: string): Promise<void> {
  await db.prepare('DELETE FROM security_bans WHERE ip_hash = ?').bind(hash).run();
  try {
    await caches.default.delete(banCacheKey(hash));
  } catch {
    /* ignore */
  }
}

async function readEdgeLoginFailures(key: Request, now: number): Promise<LoginFailureState> {
  try {
    const hit = await caches.default.match(key);
    if (hit) {
      const parsed = (await hit.json()) as Partial<LoginFailureState>;
      if (
        typeof parsed.count === 'number' &&
        typeof parsed.startedAt === 'number' &&
        parsed.startedAt > now - LOGIN_FAILURE_WINDOW_SECONDS
      ) {
        return { count: parsed.count, startedAt: parsed.startedAt };
      }
    }
  } catch {
    /* ignore */
  }
  return { count: 0, startedAt: now };
}

async function cacheLoginFailures(key: Request, state: LoginFailureState): Promise<void> {
  try {
    await caches.default.put(
      key,
      new Response(JSON.stringify(state), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${LOGIN_FAILURE_WINDOW_SECONDS}`,
        },
      }),
    );
  } catch {
    /* ignore */
  }
}

/**
 * Five failed `/lg` attempts in ten minutes trigger the same one-day ban as a
 * honeypot hit. D1 is authoritative across Cloudflare colos; edge state is a
 * graceful fallback when durable storage is temporarily unavailable.
 */
export async function recordLoginFailure(req: Request, env: Env): Promise<boolean> {
  const ip = getClientIp(req);
  if (!ip) return false;
  const hash = await ipHash(env.SECRET_KEY, ip);
  const key = loginFailureCacheKey(hash);
  const now = Math.floor(Date.now() / 1000);
  let state: LoginFailureState;

  try {
    const row = await env.DB.prepare(
      `INSERT INTO security_login_failures (ip_hash, window_started, last_failed, failure_count)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(ip_hash) DO UPDATE SET
         window_started = CASE
           WHEN security_login_failures.window_started <= excluded.last_failed - ? THEN excluded.window_started
           ELSE security_login_failures.window_started
         END,
         last_failed = excluded.last_failed,
         failure_count = CASE
           WHEN security_login_failures.window_started <= excluded.last_failed - ? THEN 1
           ELSE security_login_failures.failure_count + 1
         END
       RETURNING window_started, failure_count`,
    )
      .bind(hash, now, now, LOGIN_FAILURE_WINDOW_SECONDS, LOGIN_FAILURE_WINDOW_SECONDS)
      .first<{ window_started: number; failure_count: number }>();
    state = { count: row?.failure_count ?? 1, startedAt: row?.window_started ?? now };
    // Mirror the durable count so protection survives a later D1 outage.
    await cacheLoginFailures(key, state);
  } catch {
    state = await readEdgeLoginFailures(key, now);
    state.count += 1;
    await cacheLoginFailures(key, state);
  }

  if (state.count < LOGIN_FAILURE_LIMIT) return false;

  await banClient(req, env, 'login-bruteforce');
  try {
    await env.DB.prepare('DELETE FROM security_login_failures WHERE ip_hash = ?').bind(hash).run();
  } catch {
    /* ignore */
  }
  try {
    await caches.default.delete(key);
  } catch {
    /* ignore */
  }
  return true;
}

export async function clearLoginFailures(req: Request, env: Env): Promise<void> {
  const ip = getClientIp(req);
  if (!ip) return;
  const hash = await ipHash(env.SECRET_KEY, ip);
  try {
    await env.DB.prepare('DELETE FROM security_login_failures WHERE ip_hash = ?').bind(hash).run();
  } catch {
    /* A successful login must not fail because counter cleanup is unavailable. */
  }
  try {
    await caches.default.delete(loginFailureCacheKey(hash));
  } catch {
    /* ignore */
  }
}
