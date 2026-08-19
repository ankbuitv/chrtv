import type { Env } from '../types';
import { ErrorCodes } from '../errors/codes';
import { corsPreflight, errorResponse, jsonResponse, logEvent, methodNotAllowed } from '../utils/http';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';
import { resolvePlaylistAccess } from '../playlist/access';
import { buildChannelEntries } from '../playlist/output';
import { recordAuthEvent } from '../auth/audit';
import { createToken, DEFAULT_MANIFEST_TTL, requestTokenBinding } from '../token';
import { kindFromUrl, tokenHintsFromPlayOpts } from '../playlist/playOpts';

/**
 * Web player (/xem) API.
 *
 * GET  /api/channels — the channel grid behind the player: the exact same
 *   tokenized entries /tv.m3u serves (same identity binding, same stable
 *   deterministic tokens), rendered as JSON for the browser.
 *
 * POST /api/play — paste-and-play for operator token links: takes an m3u8 URL
 *   (query string included, e.g. ?token=…) and returns a short-lived CHRTV
 *   proxy manifest URL. The upstream URL is validated by the same SSRF/port
 *   guards the rest of the gateway uses, is never echoed back, and only ever
 *   travels encrypted inside the token — so a pasted link behaves exactly like
 *   a channel synced from the playlist (fallback/error manifests included).
 *
 * Paste-play can be disabled with ALLOW_URL_PLAY=false, and is off by default
 * when PUBLIC_PLAYLIST=false (an operator who locked the playlist down must
 * not get an arbitrary-URL proxy for free; they can still opt in explicitly).
 */

/** Hard cap on a pasted upstream URL — tokens carry it encrypted, keep it bounded. */
const MAX_PLAY_URL_LENGTH = 2048;

/** Paste-play tokens live for 6 hours, mirroring a manifest-entry TTL. */
const PLAY_TOKEN_TTL = DEFAULT_MANIFEST_TTL;

/**
 * Paste-and-play availability:
 *  - explicit ALLOW_URL_PLAY=true  => on (even in locked-down deployments)
 *  - explicit ALLOW_URL_PLAY=false => off
 *  - unset                          => follows PUBLIC_PLAYLIST (default on)
 */
export function urlPlayEnabled(env: Env): boolean {
  const explicit = (env.ALLOW_URL_PLAY ?? '').trim().toLowerCase();
  if (explicit === 'true') return true;
  if (explicit === 'false') return false;
  return (env.PUBLIC_PLAYLIST ?? 'true').toLowerCase() !== 'false';
}

export async function handleChannelsApi(req: Request, env: Env, requestId: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);

  const access = await resolvePlaylistAccess(req, env, requestId, '/api/channels');
  if (!access.ok) return access.response;
  const { binding, playlistExpiry, userId, username } = access.access;

  const { entries, epgUrl } = await buildChannelEntries(env, new URL(req.url).origin, binding, playlistExpiry, req);

  await recordAuthEvent(req, env, {
    userId,
    username,
    eventType: 'playlist',
    route: '/api/channels',
    outcome: 'success',
  });

  if (req.method === 'HEAD') {
    return new Response(null, {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
        'X-Request-ID': requestId,
      },
    });
  }
  return jsonResponse(
    { count: entries.length, epg: epgUrl, channels: entries },
    200,
    { 'Access-Control-Allow-Origin': '*', 'X-Request-ID': requestId },
  );
}

export async function handlePlayApi(req: Request, env: Env, requestId: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'POST') return methodNotAllowed(['POST', 'OPTIONS'], requestId);

  if (!urlPlayEnabled(env)) {
    logEvent(requestId, '/api/play', ErrorCodes.URL_PLAY_DISABLED);
    return errorResponse(ErrorCodes.URL_PLAY_DISABLED, 403, requestId);
  }

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
  }
  const url = typeof (raw as { url?: unknown })?.url === 'string' ? ((raw as { url: string }).url as string).trim() : '';
  if (!url) return errorResponse(ErrorCodes.BAD_REQUEST, 400, requestId);
  if (url.length > MAX_PLAY_URL_LENGTH) return errorResponse(ErrorCodes.UNSAFE_URL, 400, requestId);

  // Same defense-in-depth gates every other upstream fetch goes through.
  if (!isSafeUpstreamUrl(url)) {
    logEvent(requestId, '/api/play', ErrorCodes.UNSAFE_URL);
    return errorResponse(ErrorCodes.UNSAFE_URL, 400, requestId);
  }
  if (!isFetchablePort(url)) {
    logEvent(requestId, '/api/play', ErrorCodes.UNSUPPORTED_PORT, 'origin hidden');
    return errorResponse(ErrorCodes.UNSUPPORTED_PORT, 400, requestId);
  }

  // The pasted URL becomes an ordinary (short-lived) manifest capability:
  // encrypted, identity-bound, expiring, and served through /hls/ with all the
  // usual manifest rewriting, fallback, and circuit-breaker behaviour.
  const binding = requestTokenBinding(req, {}, env.TOKEN_BINDING);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + PLAY_TOKEN_TTL;
  const hints = tokenHintsFromPlayOpts('', url);
  const kind = kindFromUrl(url) === 'mpd' ? 'mpd' : 'hls';
  const token = await createToken(env.SECRET_KEY, { u: url, iat, exp, k: 'm', ...binding, ...hints });
  const origin = new URL(req.url).origin;
  const src = kind === 'mpd' ? `${origin}/mpd/${token}.mpd` : `${origin}/hls/${token}.m3u8`;

  await recordAuthEvent(req, env, {
    eventType: 'playlist',
    route: '/api/play',
    outcome: 'success',
  });

  logEvent(requestId, '/api/play', 'OK', 'token minted');
  return jsonResponse({ src, expires_at: exp, kind }, 200, {
    'Access-Control-Allow-Origin': '*',
    'X-Request-ID': requestId,
  });
}
