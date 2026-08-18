import type { Env } from '../types';
import { ErrorCodes } from '../errors/codes';
import { errorResponse, logEvent } from '../utils/http';
import { authenticateAccessKey } from '../auth';
import { recordAuthEvent } from '../auth/audit';
import { requestTokenBinding, type TokenBinding } from '../token';

/**
 * Shared access resolution for every consumer-facing playlist surface
 * (GET /tv.m3u, GET /api/channels for the /xem web player).
 *
 * One policy, three outcomes:
 *  - ?key= supplied => the key is ALWAYS validated (device registered by MAC);
 *  - no key + PUBLIC_PLAYLIST=true => anonymous access, tokens personalized by
 *    whatever identity Cloudflare can observe (IP / declared MAC);
 *  - no key + PUBLIC_PLAYLIST=false => 401 before anything is read from D1.
 *
 * Every token minted downstream carries the resolved binding, so revoking a
 * user/key/session still kills streams started from the web player.
 */

export interface PlaylistAccess {
  binding: TokenBinding;
  /** Capability boundary inherited from the authenticated key, if any. */
  playlistExpiry: number | null;
  userId?: number;
  username?: string;
}

export type PlaylistAccessResult = { ok: true; access: PlaylistAccess } | { ok: false; response: Response };

export async function resolvePlaylistAccess(
  req: Request,
  env: Env,
  requestId: string,
  route: string,
): Promise<PlaylistAccessResult> {
  const url = new URL(req.url);
  const publicPlaylist = (env.PUBLIC_PLAYLIST ?? 'true').toLowerCase() !== 'false';
  const key = url.searchParams.get('key') ?? url.searchParams.get('access_key');
  const mac = url.searchParams.get('mac');

  let accessKeyId: number | undefined;
  let userId: number | undefined;
  let username: string | undefined;
  let playlistExpiry: number | null | undefined;
  if (key) {
    // A key was supplied: always validate it (and register the device by MAC).
    const auth = await authenticateAccessKey(env, key, mac, req.headers.get('user-agent') ?? '');
    if (!auth.ok) {
      logEvent(requestId, route, auth.code);
      await recordAuthEvent(req, env, {
        eventType: 'access_key',
        route,
        outcome: 'failure',
      });
      return { ok: false, response: errorResponse(auth.code, auth.status, requestId) };
    }
    accessKeyId = auth.value.id;
    userId = auth.value.user_id ?? undefined;
    username = auth.value.username || undefined;
    playlistExpiry = auth.value.expires_at;
    await recordAuthEvent(req, env, {
      userId: auth.value.user_id,
      username: auth.value.username,
      eventType: 'access_key',
      route,
      outcome: 'success',
    });
  } else if (!publicPlaylist) {
    logEvent(requestId, route, ErrorCodes.KEY_INVALID, 'key required');
    await recordAuthEvent(req, env, {
      eventType: 'playlist',
      route,
      outcome: 'failure',
    });
    return { ok: false, response: errorResponse(ErrorCodes.KEY_INVALID, 401, requestId) };
  }

  // The encrypted channel tokens are personalized by every trustworthy identity
  // available here (same contract as the classic /tv.m3u route).
  const binding = requestTokenBinding(req, { rawMac: mac, userId, accessKeyId }, env.TOKEN_BINDING);
  return {
    ok: true,
    access: {
      binding,
      playlistExpiry: playlistExpiry ?? null,
      userId,
      username,
    },
  };
}
