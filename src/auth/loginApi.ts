import type { Env } from '../types';
import { authenticateUser } from './index';
import { authenticateSessionToken, createUserSession, listUserSessions, revokeUserSession } from './sessions';
import { recordAuthEvent } from './audit';
import { buildPlaylist, playlistResponse } from '../playlist/output';
import { requestTokenBinding } from '../token';
import { clearLoginFailures, recordLoginFailure, securityBanSeconds } from '../security/honeypot';
import { ErrorCodes } from '../errors/codes';
import { errorResponse, jsonResponse, methodNotAllowed } from '../utils/http';

function privateResponse(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set('Cache-Control', 'private, no-store');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function loginBody(req: Request): Promise<{
  username: string;
  password: string;
  deviceName: string;
  replaceOldest: boolean;
} | null> {
  const length = Number(req.headers.get('content-length') ?? 0);
  if (Number.isFinite(length) && length > 4096) return null;
  try {
    const body = (await req.json()) as Record<string, unknown>;
    if (!body || typeof body !== 'object') return null;
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const deviceName = typeof body.device_name === 'string' ? body.device_name.trim() : '';
    if (!username || username.length > 128 || !password || password.length > 256 || deviceName.length > 80) return null;
    return { username, password, deviceName, replaceOldest: body.replace_oldest === true };
  } catch {
    return null;
  }
}

/** POST /api/login: exchange D1 credentials for a revocable opaque playlist URL. */
export async function handleLoginApi(req: Request, env: Env, requestId: string): Promise<Response> {
  if (req.method !== 'POST') return privateResponse(methodNotAllowed(['POST'], requestId));
  const body = await loginBody(req);
  if (!body) return privateResponse(errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId));

  const auth = await authenticateUser(env, body.username, body.password);
  if (!auth.ok) {
    const newlyBanned = await recordLoginFailure(req, env);
    await recordAuthEvent(req, env, {
      username: body.username,
      eventType: 'login',
      route: '/api/login',
      outcome: newlyBanned ? 'blocked' : 'failure',
    });
    const response = newlyBanned
      ? errorResponse(ErrorCodes.SECURITY_BANNED, 429, requestId)
      : errorResponse(ErrorCodes.AUTH_INVALID, 401, requestId);
    if (newlyBanned) response.headers.set('Retry-After', String(securityBanSeconds(env)));
    return privateResponse(response);
  }

  let created = await createUserSession(req, env, auth.value, body.deviceName);
  if (!created.ok && body.replaceOldest) {
    await env.DB.prepare(
      `UPDATE user_sessions SET status = 'revoked'
        WHERE id = (SELECT id FROM user_sessions
                     WHERE user_id = ? AND status = 'active'
                     ORDER BY last_seen ASC LIMIT 1)`,
    )
      .bind(auth.value.id)
      .run();
    created = await createUserSession(req, env, auth.value, body.deviceName);
  }
  if (!created.ok) {
    await recordAuthEvent(req, env, {
      userId: auth.value.id,
      username: auth.value.username,
      eventType: 'login',
      route: '/api/login',
      outcome: 'limit',
    });
    return privateResponse(errorResponse(ErrorCodes.SESSION_LIMIT, 409, requestId));
  }

  await clearLoginFailures(req, env);
  await recordAuthEvent(req, env, {
    userId: auth.value.id,
    sessionId: created.session.id,
    username: auth.value.username,
    eventType: 'login',
    route: '/api/login',
    outcome: 'success',
  });
  const origin = new URL(req.url).origin;
  return privateResponse(
    jsonResponse(
      {
        ok: true,
        access_token: created.token,
        playlist_url: `${origin}/p/${created.token}.m3u`,
        session: {
          id: created.session.id,
          device_name: created.session.device_name,
          created_at: created.session.created_at,
          expires_at: created.session.expires_at,
        },
      },
      201,
    ),
  );
}

/** GET /p/{session}.m3u: refreshable M3U without a password in its URL. */
export async function handleSessionPlaylist(
  req: Request,
  env: Env,
  requestId: string,
  rawToken: string,
): Promise<Response> {
  if (!['GET', 'HEAD'].includes(req.method)) return privateResponse(methodNotAllowed(['GET', 'HEAD'], requestId));
  const token = rawToken.replace(/\.m3u$/i, '');
  if (!/^[a-f0-9]{64}$/.test(token) || rawToken !== `${token}.m3u`) {
    return privateResponse(errorResponse(ErrorCodes.AUTH_INVALID, 401, requestId));
  }
  const auth = await authenticateSessionToken(req, env, token, true);
  if (!auth.ok) {
    await recordAuthEvent(req, env, {
      eventType: 'playlist',
      route: '/p/:session.m3u',
      outcome: 'failure',
    });
    return privateResponse(errorResponse(auth.code, auth.status, requestId));
  }

  const { session, user } = auth.value;
  await recordAuthEvent(req, env, {
    userId: user.id,
    sessionId: session.id,
    username: user.username,
    eventType: 'playlist',
    route: '/p/:session.m3u',
    outcome: 'success',
  });
  const url = new URL(req.url);
  const binding = requestTokenBinding(req, { userId: user.id, sessionId: session.id }, env.TOKEN_BINDING);
  const expiryCandidates = [session.expires_at, user.expires_at].filter(
    (value): value is number => value !== null && Number.isFinite(value) && value > 0,
  );
  const effectiveExpiry = expiryCandidates.length > 0 ? Math.min(...expiryCandidates) : null;
  const body = await buildPlaylist(env, url.origin, binding, effectiveExpiry);
  return privateResponse(playlistResponse(body, requestId, req.method === 'HEAD'));
}

/** Bearer-session self-service: list and revoke only the current user's sessions. */
export async function handleAccountApi(
  req: Request,
  env: Env,
  requestId: string,
  subPath: string,
): Promise<Response> {
  const auth = await authenticateSessionToken(req, env, undefined, true);
  if (!auth.ok) return privateResponse(errorResponse(auth.code, auth.status, requestId));
  const { session, user } = auth.value;

  if (subPath === 'sessions' && req.method === 'GET') {
    const sessions = await listUserSessions(env, user.id);
    return privateResponse(
      jsonResponse({
        user: { id: user.id, username: user.username, max_connections: user.max_connections, expires_at: user.expires_at },
        current_session_id: session.id,
        sessions,
      }),
    );
  }

  const match = subPath.match(/^sessions\/(\d+)$/);
  if (match) {
    if (req.method !== 'DELETE') return privateResponse(methodNotAllowed(['DELETE'], requestId));
    const removed = await revokeUserSession(env, user.id, Number(match[1]));
    return privateResponse(removed ? jsonResponse({ ok: true }) : errorResponse(ErrorCodes.NOT_FOUND, 404, requestId));
  }

  return privateResponse(errorResponse(ErrorCodes.NOT_FOUND, 404, requestId));
}
