import type { Env } from '../types';
import { verifyToken } from '../token';
import { ErrorCodes } from '../errors/codes';
import { errorResponse, logEvent, methodNotAllowed, corsPreflight } from '../utils/http';
import { fetchUpstream, passthroughResponse } from './upstream';
import { isFetchablePort } from '../utils/ports';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { rewriteManifest, looksLikeHls, HlsError } from '../hls/rewrite';
import { errorManifestResponse } from '../hls/errorManifest';
import { getFailure, setFailure, recordFailure } from './failureCache';
import { sha256Hex } from '../utils/crypto';

/**
 * Stream proxy handlers.
 *
 * /hls/{token}.m3u8 — manifest proxy: fetch upstream, rewrite URIs against the
 *   FINAL upstream URL, re-tokenize, return. Upstream failures for an
 *   authenticated token => fallback playlist (FALLBACK_M3U_URL, re-proxied)
 *   or the empty error manifest (HTTP 200), never HTML.
 * /seg/{token}[.ext] — media passthrough: body is streamed, Range/206
 *   preserved, nothing buffered. Media failures => plain HTTP errors
 *   (players fall back to re-fetching the manifest, which serves the fallback).
 *
 * Auth failures (bad/expired token) => real HTTP errors. The fallback manifest
 * never masks authentication problems.
 */

function stripExt(raw: string): string {
  const dot = raw.indexOf('.');
  return dot === -1 ? raw : raw.slice(0, dot);
}

async function failureKey(payload: { c?: string; u: string }): Promise<string> {
  // Channel-level key when known; otherwise URL-hash so one dead rendition
  // doesn't take down the entire channel entry.
  return payload.c ?? (await sha256Hex(payload.u)).slice(0, 16);
}

/**
 * Fallback playlist candidates.
 * FALLBACK_M3U_URL may list several URLs (comma / whitespace separated); they
 * are tried in order, so an operator can put a proxyable https source first and
 * keep a custom-port one as the last resort.
 */
export function fallbackCandidates(env: Env): string[] {
  return (env.FALLBACK_M3U_URL ?? '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && isSafeUpstreamUrl(s))
    .slice(0, 5);
}

/**
 * Redirect the PLAYER straight to the fallback stream.
 * Used when the fallback lives on a port Cloudflare Workers cannot open a
 * subrequest to (e.g. :30113) — the worker can never fetch it, but the player
 * on the user's device has no such restriction, so a 302 makes the fallback
 * actually play instead of silently degrading to the empty "signal lost"
 * manifest. Same trick already used for channels on custom ports.
 */
function fallbackRedirect(target: string, requestId: string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: target,
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
      'X-CHRTV-Fallback': '1',
    },
  });
}

/**
 * Serve the fallback playlist when a channel upstream is dead.
 * 1. Any candidate on a Workers-fetchable port is fetched + rewritten, so the
 *    player gets a playable stream proxied through CHRTV (segments become
 *    /seg/{token}, everything stays on the worker origin — no mixed content).
 * 2. If no candidate could be proxied but one lives on a port the worker cannot
 *    reach, the player is 302-redirected to it and plays it directly.
 * 3. Only when nothing is configured/usable do we return the empty error
 *    manifest (a valid ENDED playlist) so players never get HTML.
 */
async function serveFallbackManifest(env: Env, req: Request, requestId: string): Promise<Response> {
  const candidates = fallbackCandidates(env);
  if (candidates.length === 0) return errorManifestResponse(requestId);

  // Candidates the worker cannot fetch itself, kept for the redirect path.
  const directOnly: string[] = [];

  for (const fallbackUrl of candidates) {
    if (!isFetchablePort(fallbackUrl)) {
      // Fetching it would hang until the timeout on EVERY dead-channel request;
      // hand it to the player instead (step 2 below).
      directOnly.push(fallbackUrl);
      continue;
    }

    const upstream = await fetchUpstream(fallbackUrl, req, 'GET', 'manifest');
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

  if (directOnly.length > 0) {
    logEvent(requestId, '/hls', 'FALLBACK_REDIRECT', 'unsupported-port');
    return fallbackRedirect(directOnly[0]!, requestId);
  }

  return errorManifestResponse(requestId);
}

export async function handleHlsManifest(req: Request, env: Env, requestId: string, rawToken: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);

  const token = stripExt(rawToken);
  const verdict = await verifyToken(env.SECRET_KEY, token);
  if (!verdict.ok) {
    logEvent(requestId, '/hls', verdict.code);
    const status = verdict.code === 'TOKEN_EXPIRED' ? 410 : 403;
    return errorResponse(ErrorCodes[verdict.code], status, requestId);
  }
  const payload = verdict.payload;

  // Ports that Cloudflare Workers cannot open subrequests to are redirected
  // directly so the client player can stream them directly.
  if (!isFetchablePort(payload.u)) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: payload.u,
        'Access-Control-Allow-Origin': '*',
        'X-Request-ID': requestId,
      },
    });
  }

  const fkey = await failureKey(payload);

  // Circuit breaker: known-dead upstream inside TTL => immediate fallback manifest.
  const failed = await getFailure(fkey);
  if (failed) {
    logEvent(requestId, '/hls', 'CIRCUIT_OPEN', failed.code);
    return serveFallbackManifest(env, req, requestId);
  }

  const upstream = await fetchUpstream(payload.u, req, 'GET', 'manifest');
  if (!upstream.ok) {
    logEvent(requestId, '/hls', upstream.code, `status=${upstream.status}`);
    await setFailure(fkey, { code: upstream.code, status: upstream.status, at: Date.now() });
    if (payload.c) await recordFailure(env.DB, payload.c, upstream.code, upstream.status);
    return serveFallbackManifest(env, req, requestId);
  }

  let text: string;
  try {
    text = await upstream.response.text();
  } catch {
    await setFailure(fkey, { code: ErrorCodes.UPSTREAM_UNREACHABLE, status: 0, at: Date.now() });
    return serveFallbackManifest(env, req, requestId);
  }

  if (!looksLikeHls(text) || text.trim().length === 0) {
    logEvent(requestId, '/hls', ErrorCodes.INVALID_HLS);
    await setFailure(fkey, { code: ErrorCodes.INVALID_HLS, status: upstream.response.status, at: Date.now() });
    if (payload.c) await recordFailure(env.DB, payload.c, ErrorCodes.INVALID_HLS, upstream.response.status);
    return serveFallbackManifest(env, req, requestId);
  }

  let rewritten: string;
  try {
    rewritten = await rewriteManifest(text, {
      secret: env.SECRET_KEY,
      baseUrl: upstream.finalUrl, // relative URIs resolve against the FINAL (post-redirect) URL
      publicOrigin: new URL(req.url).origin,
    });
  } catch (err) {
    logEvent(requestId, '/hls', ErrorCodes.INVALID_HLS, err instanceof HlsError ? err.message : 'rewrite failed');
    return serveFallbackManifest(env, req, requestId);
  }

  return new Response(req.method === 'HEAD' ? null : rewritten, {
    status: 200,
    headers: {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
    },
  });
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

  if (!isFetchablePort(verdict.payload.u)) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: verdict.payload.u,
        'Access-Control-Allow-Origin': '*',
        'X-Request-ID': requestId,
      },
    });
  }

  const isHead = req.method === 'HEAD';
  const upstream = await fetchUpstream(verdict.payload.u, req, isHead ? 'HEAD' : 'GET', 'segment');
  if (!upstream.ok) {
    logEvent(requestId, '/seg', upstream.code, `status=${upstream.status}`);
    // Media failures return real HTTP errors; players re-request the manifest,
    // where the circuit breaker serves the fallback.
    const status = upstream.code === ErrorCodes.UPSTREAM_TIMEOUT ? 504 : upstream.status >= 400 ? 502 : 502;
    return errorResponse(upstream.code, status, requestId);
  }

  // Note: no breaker bookkeeping here — the failure state self-expires after
  // its short TTL, keeping the segment hot path down to token check + fetch.
  return passthroughResponse(upstream.response, requestId, isHead);
}
