import type { Env } from '../types';
import { requestMatchesTokenBinding, tokenBindingFromPayload, verifyToken, type TokenBinding, type TokenPayload } from '../token';
import { ErrorCodes } from '../errors/codes';
import { errorResponse, logEvent, methodNotAllowed, corsPreflight } from '../utils/http';
import { fetchUpstream, passthroughResponse, hintsFromPayload, type UpstreamHints } from './upstream';
import { isFetchablePort } from '../utils/ports';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import {
  rewriteManifest,
  looksLikeHls,
  HlsError,
  isWrapperManifest,
  firstWrapperUri,
  looksLikeBareUpstreamUrl,
} from '../hls/rewrite';
import { rewriteMpd, looksLikeMpd, joinDashPath, DashError } from '../dash/rewrite';
import { errorManifestResponse } from '../hls/errorManifest';
import { errorMpdResponse } from '../dash/errorMpd';
import { getFailure, setFailure, recordFailure } from './failureCache';
import { sha256Hex } from '../utils/crypto';
import { isTokenAuthorizationActive } from '../auth/tokenAuthorization';
import { touchViewerLease } from '../playlist/viewLease';

/**
 * Stream proxy handlers.
 *
 * /hls/{token}.m3u8  — HLS (or sniffed DASH) manifest proxy
 * /mpd/{token}.mpd   — DASH manifest proxy (same token kind `m`)
 * /seg/{token}[.ext] — media passthrough
 * /dseg/{token}/{path} — DASH SegmentTemplate prefix (token kind `b`)
 *
 * Nested "proxy → other m3u8" wrappers (PHP portals that return a 1-line
 * M3U pointing at the real playlist, or even a bare URL) are followed here
 * before rewriting, so the player always receives a real media/master
 * playlist or a rewritten MPD — never a wrapper that hls.js would try to
 * demux as MPEG-TS.
 */

const MAX_UNWRAP_HOPS = 2;

function stripExt(raw: string): string {
  const dot = raw.indexOf('.');
  return dot === -1 ? raw : raw.slice(0, dot);
}

async function failureKey(payload: { c?: string; u: string }): Promise<string> {
  return payload.c ?? (await sha256Hex(payload.u)).slice(0, 16);
}

function rewriteOpts(
  env: Env,
  req: Request,
  payload: TokenPayload,
  binding: TokenBinding,
  baseUrl: string,
) {
  const hints = hintsFromPayload(payload);
  return {
    secret: env.SECRET_KEY,
    baseUrl,
    publicOrigin: new URL(req.url).origin,
    binding,
    ...(payload.c ? { channelId: payload.c } : {}),
    ...(payload.l ? { leaseId: payload.l } : {}),
    absoluteExpiry: payload.exp,
    ...hints,
  };
}

export function fallbackCandidates(env: Env): string[] {
  return (env.FALLBACK_M3U_URL ?? '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && isSafeUpstreamUrl(s))
    .slice(0, 5);
}

async function serveFallbackManifest(
  env: Env,
  req: Request,
  requestId: string,
  binding: TokenBinding = {},
  channelId?: string,
  absoluteExpiry?: number,
  reason?: string,
  asMpd = false,
): Promise<Response> {
  if (asMpd) return errorMpdResponse(requestId, reason);

  const candidates = fallbackCandidates(env);
  if (candidates.length === 0) return errorManifestResponse(requestId, reason);

  for (const fallbackUrl of candidates) {
    if (!isFetchablePort(fallbackUrl)) {
      logEvent(requestId, '/hls', 'FALLBACK_UNSUPPORTED_PORT', 'origin hidden');
      continue;
    }

    const upstream = await fetchUpstream(fallbackUrl, req, 'GET', 'manifest', env);
    if (!upstream.ok) {
      logEvent(requestId, '/hls', 'FALLBACK_FETCH_FAILED', upstream.code);
      continue;
    }

    let text: string;
    try {
      text = await upstream.response.text();
    } catch {
      continue;
    }

    if (!looksLikeHls(text) || text.trim().length === 0) {
      logEvent(requestId, '/hls', 'FALLBACK_INVALID', '');
      continue;
    }

    let rewritten: string;
    try {
      rewritten = await rewriteManifest(text, {
        secret: env.SECRET_KEY,
        baseUrl: upstream.finalUrl,
        publicOrigin: new URL(req.url).origin,
        binding,
        ...(channelId ? { channelId } : {}),
        ...(absoluteExpiry !== undefined ? { absoluteExpiry } : {}),
      });
    } catch {
      continue;
    }

    return new Response(req.method === 'HEAD' ? null : rewritten, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
        'X-Request-ID': requestId,
        'X-CHRTV-Fallback': '1',
      },
    });
  }

  return errorManifestResponse(requestId, reason);
}

/**
 * Follow wrapper playlists / bare-URL bodies until we land on a real HLS
 * master/media playlist or an MPD. Each hop is SSRF + port checked by
 * fetchUpstream. Capped so a malicious chain cannot burn the subrequest budget.
 */
async function unwrapNested(
  text: string,
  finalUrl: string,
  req: Request,
  env: Env,
  hints: UpstreamHints,
): Promise<{ text: string; finalUrl: string }> {
  let currentText = text;
  let currentUrl = finalUrl;
  for (let hop = 0; hop < MAX_UNWRAP_HOPS; hop++) {
    const bare = looksLikeBareUpstreamUrl(currentText);
    const wrapper = !bare && isWrapperManifest(currentText, currentUrl);
    const next = bare ?? (wrapper ? firstWrapperUri(currentText, currentUrl) : null);
    if (!next) break;
    if (!isSafeUpstreamUrl(next) || !isFetchablePort(next)) break;
    const upstream = await fetchUpstream(next, req, 'GET', 'manifest', env, hints);
    if (!upstream.ok) break;
    let nextText: string;
    try {
      nextText = await upstream.response.text();
    } catch {
      break;
    }
    if (!nextText.trim()) break;
    currentText = nextText;
    currentUrl = upstream.finalUrl;
    if (looksLikeMpd(currentText)) break;
    if (looksLikeHls(currentText) && !isWrapperManifest(currentText, currentUrl) && !looksLikeBareUpstreamUrl(currentText)) {
      break;
    }
  }
  return { text: currentText, finalUrl: currentUrl };
}

function manifestResponse(req: Request, body: string, requestId: string, contentType: string, fallback = false): Response {
  return new Response(req.method === 'HEAD' ? null : body, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
      ...(fallback ? { 'X-CHRTV-Fallback': '1' } : {}),
    },
  });
}

async function serveRewrittenManifest(
  env: Env,
  req: Request,
  requestId: string,
  payload: TokenPayload,
  binding: TokenBinding,
  text: string,
  finalUrl: string,
  preferMpd: boolean,
): Promise<Response> {
  const opts = rewriteOpts(env, req, payload, binding, finalUrl);

  if (looksLikeMpd(text)) {
    try {
      const rewritten = await rewriteMpd(text, opts);
      return manifestResponse(req, rewritten, requestId, 'application/dash+xml');
    } catch (err) {
      logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.INVALID_HLS, err instanceof DashError ? err.message : 'mpd rewrite failed');
      return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.INVALID_HLS, preferMpd);
    }
  }

  if (looksLikeHls(text) && text.trim().length > 0) {
    try {
      const rewritten = await rewriteManifest(text, opts);
      return manifestResponse(req, rewritten, requestId, 'application/vnd.apple.mpegurl');
    } catch (err) {
      logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.INVALID_HLS, err instanceof HlsError ? err.message : 'rewrite failed');
      return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.INVALID_HLS, preferMpd);
    }
  }

  logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.INVALID_HLS);
  return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.INVALID_HLS, preferMpd);
}

async function handleManifest(
  req: Request,
  env: Env,
  requestId: string,
  rawToken: string,
  preferMpd: boolean,
): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);

  const token = stripExt(rawToken);
  const verdict = await verifyToken(env.SECRET_KEY, token);
  if (!verdict.ok) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', verdict.code);
    const status = verdict.code === 'TOKEN_EXPIRED' ? 410 : 403;
    return errorResponse(ErrorCodes[verdict.code], status, requestId);
  }
  const payload = verdict.payload;
  if (payload.k !== 'm') {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.TOKEN_INVALID, 'wrong token kind');
    return errorResponse(ErrorCodes.TOKEN_INVALID, 403, requestId);
  }
  if (!requestMatchesTokenBinding(req, payload)) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.TOKEN_BINDING_MISMATCH);
    return errorResponse(ErrorCodes.TOKEN_BINDING_MISMATCH, 403, requestId);
  }
  if (!(await touchViewerLease(env, payload))) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.TOKEN_EXPIRED, 'viewer lease idle or rotated');
    return errorResponse(ErrorCodes.TOKEN_EXPIRED, 410, requestId);
  }
  if (!(await isTokenAuthorizationActive(env, payload))) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.AUTH_DISABLED, 'revoked or expired token identity');
    return errorResponse(ErrorCodes.AUTH_DISABLED, 403, requestId);
  }
  const binding = tokenBindingFromPayload(payload);
  const hints = hintsFromPayload(payload);

  if (!isFetchablePort(payload.u)) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.UNSUPPORTED_PORT, 'origin hidden');
    if (payload.c) await recordFailure(env.DB, payload.c, ErrorCodes.UNSUPPORTED_PORT, 0);
    return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.UNSUPPORTED_PORT, preferMpd);
  }

  const fkey = await failureKey(payload);
  const failed = await getFailure(fkey);
  if (failed) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', 'CIRCUIT_OPEN', failed.code);
    return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, failed.code, preferMpd);
  }

  const upstream = await fetchUpstream(payload.u, req, 'GET', 'manifest', env, hints);
  if (!upstream.ok) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', upstream.code, `status=${upstream.status}`);
    await setFailure(fkey, { code: upstream.code, status: upstream.status, at: Date.now() });
    if (payload.c) await recordFailure(env.DB, payload.c, upstream.code, upstream.status);
    return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, upstream.code, preferMpd);
  }

  let text: string;
  try {
    text = await upstream.response.text();
  } catch {
    await setFailure(fkey, { code: ErrorCodes.UPSTREAM_UNREACHABLE, status: 0, at: Date.now() });
    return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.UPSTREAM_UNREACHABLE, preferMpd);
  }

  const unwrapped = await unwrapNested(text, upstream.finalUrl, req, env, hints);
  text = unwrapped.text;

  if ((!looksLikeHls(text) && !looksLikeMpd(text)) || text.trim().length === 0) {
    logEvent(requestId, preferMpd ? '/mpd' : '/hls', ErrorCodes.INVALID_HLS);
    await setFailure(fkey, { code: ErrorCodes.INVALID_HLS, status: upstream.response.status, at: Date.now() });
    if (payload.c) await recordFailure(env.DB, payload.c, ErrorCodes.INVALID_HLS, upstream.response.status);
    return serveFallbackManifest(env, req, requestId, binding, payload.c, payload.exp, ErrorCodes.INVALID_HLS, preferMpd);
  }

  return serveRewrittenManifest(env, req, requestId, payload, binding, text, unwrapped.finalUrl, preferMpd);
}

export async function handleHlsManifest(req: Request, env: Env, requestId: string, rawToken: string): Promise<Response> {
  return handleManifest(req, env, requestId, rawToken, false);
}

export async function handleMpdManifest(req: Request, env: Env, requestId: string, rawToken: string): Promise<Response> {
  return handleManifest(req, env, requestId, rawToken, true);
}

export async function handleSegment(req: Request, env: Env, requestId: string, rawToken: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);

  const token = stripExt(rawToken);
  const verdict = await verifyToken(env.SECRET_KEY, token);
  if (!verdict.ok) {
    logEvent(requestId, '/seg', verdict.code);
    const status = verdict.code === 'TOKEN_EXPIRED' ? 410 : 403;
    return errorResponse(ErrorCodes[verdict.code], status, requestId);
  }

  if (verdict.payload.k !== 's') {
    logEvent(requestId, '/seg', ErrorCodes.TOKEN_INVALID, 'wrong token kind');
    return errorResponse(ErrorCodes.TOKEN_INVALID, 403, requestId);
  }
  if (!requestMatchesTokenBinding(req, verdict.payload)) {
    logEvent(requestId, '/seg', ErrorCodes.TOKEN_BINDING_MISMATCH);
    return errorResponse(ErrorCodes.TOKEN_BINDING_MISMATCH, 403, requestId);
  }

  if (!isFetchablePort(verdict.payload.u)) {
    logEvent(requestId, '/seg', ErrorCodes.UNSUPPORTED_PORT, 'origin hidden');
    return errorResponse(ErrorCodes.UNSUPPORTED_PORT, 502, requestId);
  }

  const isHead = req.method === 'HEAD';
  const hints = hintsFromPayload(verdict.payload);
  const upstream = await fetchUpstream(verdict.payload.u, req, isHead ? 'HEAD' : 'GET', 'segment', env, hints);
  if (!upstream.ok) {
    logEvent(requestId, '/seg', upstream.code, `status=${upstream.status}`);
    const status = upstream.code === ErrorCodes.UPSTREAM_TIMEOUT ? 504 : 502;
    return errorResponse(upstream.code, status, requestId);
  }

  return passthroughResponse(upstream.response, requestId, isHead);
}

/**
 * /dseg/{token}/{suffix} — DASH SegmentTemplate expansion.
 * `token` (kind `b`) encodes the upstream directory; `suffix` is the
 * player-expanded relative path (`seg_12.m4s`). Path traversal and
 * absolute suffixes are rejected before any fetch.
 */
export async function handleDashSegment(req: Request, env: Env, requestId: string, rest: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);

  const slash = rest.indexOf('/');
  const rawToken = slash === -1 ? rest : rest.slice(0, slash);
  const suffix = slash === -1 ? '' : rest.slice(slash + 1);
  const token = rawToken.replace(/\.[^.]+$/, '');
  const verdict = await verifyToken(env.SECRET_KEY, token);
  if (!verdict.ok) {
    logEvent(requestId, '/dseg', verdict.code);
    const status = verdict.code === 'TOKEN_EXPIRED' ? 410 : 403;
    return errorResponse(ErrorCodes[verdict.code], status, requestId);
  }
  if (verdict.payload.k !== 'b') {
    logEvent(requestId, '/dseg', ErrorCodes.TOKEN_INVALID, 'wrong token kind');
    return errorResponse(ErrorCodes.TOKEN_INVALID, 403, requestId);
  }
  if (!requestMatchesTokenBinding(req, verdict.payload)) {
    logEvent(requestId, '/dseg', ErrorCodes.TOKEN_BINDING_MISMATCH);
    return errorResponse(ErrorCodes.TOKEN_BINDING_MISMATCH, 403, requestId);
  }

  const joined = joinDashPath(verdict.payload.u, suffix);
  if (!joined || !isSafeUpstreamUrl(joined) || !isFetchablePort(joined)) {
    logEvent(requestId, '/dseg', ErrorCodes.UNSAFE_URL, 'rejected suffix');
    return errorResponse(ErrorCodes.UNSAFE_URL, 400, requestId);
  }

  const isHead = req.method === 'HEAD';
  const hints = hintsFromPayload(verdict.payload);
  const upstream = await fetchUpstream(joined, req, isHead ? 'HEAD' : 'GET', 'segment', env, hints);
  if (!upstream.ok) {
    logEvent(requestId, '/dseg', upstream.code, `status=${upstream.status}`);
    const status = upstream.code === ErrorCodes.UPSTREAM_TIMEOUT ? 504 : 502;
    return errorResponse(upstream.code, status, requestId);
  }
  return passthroughResponse(upstream.response, requestId, isHead);
}
