import type { Env } from '../types';
import { authenticateUser } from './index';
import { buildPlaylist, playlistResponse } from '../playlist/output';
import { ErrorCodes } from '../errors/codes';
import { errorResponse } from '../utils/http';
import { requestTokenBinding } from '../token';
import { clearLoginFailures, recordLoginFailure, securityBanSeconds } from '../security/honeypot';
import { recordAuthEvent } from './audit';

export interface PrivateLoginCredentials {
  username: string;
  password: string;
}

/**
 * Parse the intentionally compact private URL form:
 *   /lg/{username}?{password}.m3u
 *
 * The query has no key name. Percent encoding is accepted so credentials that
 * contain URL-reserved characters can still be represented safely.
 */
export function parsePrivateLogin(url: URL): PrivateLoginCredentials | null {
  const match = url.pathname.match(/^\/lg\/([^/]+)$/);
  if (!match?.[1] || !url.search || /[&=]/.test(url.search)) return null;
  const rawPassword = url.search.slice(1);
  if (!rawPassword.toLowerCase().endsWith('.m3u')) return null;

  try {
    const username = decodeURIComponent(match[1]);
    const password = decodeURIComponent(rawPassword.slice(0, -4));
    if (!username || username.includes('/') || username.length > 128) return null;
    if (!password || password.length > 256) return null;
    return { username, password };
  } catch {
    return null;
  }
}

function privateHeaders(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set('Cache-Control', 'private, no-store');
  headers.set('Referrer-Policy', 'no-referrer');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

export async function handlePrivateLogin(req: Request, env: Env, requestId: string): Promise<Response> {
  const credentials = parsePrivateLogin(new URL(req.url));
  if (!credentials) return privateHeaders(errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId));

  const auth = await authenticateUser(env, credentials.username, credentials.password);
  if (!auth.ok) {
    const newlyBanned = await recordLoginFailure(req, env);
    await recordAuthEvent(req, env, {
      username: credentials.username,
      eventType: 'playlist',
      route: '/lg/:username',
      outcome: newlyBanned ? 'blocked' : 'failure',
    });
    const response = newlyBanned
      ? errorResponse(ErrorCodes.SECURITY_BANNED, 429, requestId)
      : errorResponse(ErrorCodes.AUTH_INVALID, 401, requestId);
    if (newlyBanned) response.headers.set('Retry-After', String(securityBanSeconds(env)));
    return privateHeaders(response);
  }

  await clearLoginFailures(req, env);
  await recordAuthEvent(req, env, {
    userId: auth.value.id,
    username: auth.value.username,
    eventType: 'playlist',
    route: '/lg/:username',
    outcome: 'success',
  });
  const url = new URL(req.url);
  const binding = requestTokenBinding(req, { userId: auth.value.id }, env.TOKEN_BINDING);
  const body = await buildPlaylist(env, url.origin, binding, auth.value.expires_at, req);
  return privateHeaders(playlistResponse(body, requestId, req.method === 'HEAD'));
}
