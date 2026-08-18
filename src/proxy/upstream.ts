import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';
import { getClientIp, type TokenPayload } from '../token';
import { ErrorCodes, type ErrorCode } from '../errors/codes';
import { parseTokenHeaders } from '../playlist/playOpts';
import type { Env } from '../types';

/** Upstream request hints inherited from the (encrypted) stream token. */
export interface UpstreamHints {
  rf?: string;
  ua?: string;
  xh?: string;
}

export function hintsFromPayload(payload: Pick<TokenPayload, 'rf' | 'ua' | 'xh'>): UpstreamHints {
  const hints: UpstreamHints = {};
  if (payload.rf) hints.rf = payload.rf;
  if (payload.ua) hints.ua = payload.ua;
  if (payload.xh) hints.xh = payload.xh;
  return hints;
}

/**
 * Operator policy: an upstream is only declared dead after **30s of silence**.
 * Slow relays (e.g. devda.undo.it bouncing to the real CDN) routinely take
 * 10-25s to first byte — slow to tune in, but perfectly watchable. Cutting
 * them off at 6-8s tripped the circuit breaker on healthy channels, which is
 * exactly how "a healthy channel ends up flagged offline" happens.
 * Kept as two constants so operators can still tune manifest vs segment
 * separately, but both default to the same 30s ceiling. (Player-side fetch
 * waits don't count against Workers CPU time, only wall clock.)
 *
 * IMPORTANT: this is a TOTAL wall-clock budget for the whole request —
 * shared across every redirect hop AND the transient-failure retry. The old
 * code armed a fresh 30s timer per hop, so a slow 6-hop redirect chain could
 * keep a player staring at a spinner for up to ~3 minutes ("video loads way
 * too long") before the fallback ever appeared. Now the player waits at most
 * ~30s worst case, same as the declared policy.
 */
const MANIFEST_TIMEOUT_MS = 30_000;
const SEGMENT_TIMEOUT_MS = 30_000;

/**
 * Edge-cache TTL for media segments (seconds).
 * Live HLS segments are immutable once published, and the deterministic
 * segment tokens keep the same /seg/ URL across manifest refreshes — so the
 * SAME upstream segment is requested over and over (player retries, multiple
 * viewers, ABR ladder switches). Caching them on the Cloudflare edge means
 * only the FIRST request pays the slow-relay TTFB; everyone else gets the
 * segment instantly instead of re-suffering a 10-25s upstream each time.
 * Kept short: segments only need to live as long as they stay in the live
 * window. Range requests bypass this (see fetchOnce) — CF handles ranges over
 * a cached object itself, but a range-initiated MISS must not poison the key.
 */
const SEGMENT_CACHE_TTL_SECONDS = 30;

/**
 * Edge micro-cache TTL for manifest fetches (seconds).
 * Manifests are the tune-in hot path: a player opening one channel costs
 * 2 sequential upstream fetches (master/variant, then media playlist), and
 * every live poll of the media playlist hits the upstream again. With a slow
 * relay that makes channels painful to open and multiplies parallel
 * connections against upstreams that limit or fingerprint per-token usage.
 * A few seconds of edge caching dedupes simultaneous viewers and rapid
 * player polling into ~1 upstream fetch per colo per TTL — dramatically
 * fewer upstream connections, much faster zap-back to a recently-watched
 * channel, while a ≤4s staleness stays well inside any sane live window.
 * 2xx AND short-lived redirect responses are cached (relays often pay their
 * entire latency budget on the 302 hop); error statuses are never cached.
 */
const MANIFEST_CACHE_TTL_SECONDS = 4;

/**
 * Request headers forwarded to the upstream. Auth/cookies are never forwarded.
 * `accept-encoding` is deliberately NOT forwarded: the Workers runtime
 * transparently decodes compressed bodies, which then no longer match the
 * upstream `Content-Length` and makes players see truncated segments.
 *
 * `if-none-match` / `if-modified-since` are NOT forwarded on purpose: through
 * a shared edge cache a conditional request is a footgun. A 304 answer has an
 * EMPTY body — the proxy would treat it as an "ok" manifest, and with edge
 * caching enabled the empty 304 could even be cached and re-served to every
 * other viewer (players like VLC/hls.js don't send conditional headers for
 * HLS anyway; manifest freshness comes from the tiny cache TTL above).
 */
const FORWARD_REQUEST_HEADERS = ['range', 'accept'];

/** Response headers preserved from the upstream (Content-Length handled separately). */
const PRESERVE_RESPONSE_HEADERS = ['content-type', 'content-range', 'accept-ranges', 'etag', 'last-modified', 'date'];

export type UpstreamKind = 'manifest' | 'segment';

export type UpstreamResult =
  | { ok: true; response: Response; finalUrl: string }
  | { ok: false; code: ErrorCode; status: number };

export function classifyUpstreamStatus(status: number): ErrorCode {
  if (status === 404 || status === 410) return ErrorCodes.UPSTREAM_404;
  if (status >= 500) return ErrorCodes.UPSTREAM_5XX;
  return ErrorCodes.UPSTREAM_4XX;
}

const MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

async function cancelBody(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    /* ignore */
  }
}

/**
 * Transient failures worth one immediate retry — fast-failing kinds only
 * (connection refused / 5xx come back instantly, so a retry costs nothing).
 * A 30s timeout is NOT a hiccup, it is already a conclusive verdict; retrying
 * it would just stretch "30s until offline" into 60s before the player ever
 * sees the fallback.
 */
function isRetryable(code: ErrorCode): boolean {
  return code === ErrorCodes.UPSTREAM_UNREACHABLE || code === ErrorCodes.UPSTREAM_5XX;
}

/**
 * Edge-cache config for an upstream fetch.
 * Only successful (2xx) bodies are ever cached — a transient 4xx/5xx must
 * never be pinned to the edge for TTL seconds, or one hiccup would replay
 * the same error to every viewer until the TTL expired (the segment cache
 * previously used a blanket cacheTtl, which did exactly that).
 * Manifests additionally cache the redirect responses themselves (3xx):
 * relays put most of their latency on that hop, and caching it briefly is
 * the difference between a 12s and a 0.1s tune-in when several requests to
 * the same relay URL arrive together. Conditional requests are never sent
 * (see FORWARD_REQUEST_HEADERS), so an empty-body 304 cannot be produced or
 * poison a cache entry. Range requests are never cache-initiators.
 */
function upstreamCacheCf(kind: UpstreamKind, method: 'GET' | 'HEAD', headers: Headers): RequestInitCfProperties | undefined {
  if (method !== 'GET' || headers.has('range')) return undefined;
  if (kind === 'segment') {
    return { cacheEverything: true, cacheTtlByStatus: { '200-299': SEGMENT_CACHE_TTL_SECONDS } };
  }
  return {
    cacheEverything: true,
    cacheTtlByStatus: {
      '200-299': MANIFEST_CACHE_TTL_SECONDS,
      '300-399': MANIFEST_CACHE_TTL_SECONDS,
    },
  };
}

/**
 * Opt-in (`FORWARD_CLIENT_IP=true`): attach the Cloudflare-observed viewer IP
 * as X-Forwarded-For / X-Real-IP on upstream fetches. Off by default because
 * handing client IPs to arbitrary upstreams is a privacy smell — but some
 * operator-owned relays (e.g. a "playnow"-style box in front of a MAC/portal
 * account) authorize, geo-fence or rate-limit by the CLIENT ip they see.
 * Without this they see a Cloudflare datacenter address (a different one per
 * colo) and correctly conclude something odd is going on: direct VLC from
 * home works, the exact same link through the proxy gets 403s. With the flag
 * on, the relay can apply its per-viewer logic to the real viewer instead.
 */
function applyClientIpForward(headers: Headers, clientReq: Request, env?: Env): void {
  if (!env || (env.FORWARD_CLIENT_IP ?? '').trim().toLowerCase() !== 'true') return;
  const ip = getClientIp(clientReq);
  if (!ip) return;
  headers.set('X-Forwarded-For', ip);
  headers.set('X-Real-IP', ip);
}

function applyHints(headers: Headers, url: string, hints?: UpstreamHints): void {
  if (hints?.ua) headers.set('User-Agent', hints.ua);
  // Default Referer is the origin of the URL being fetched — the usual
  // anti-leech check. A playlist-declared Referer (token `rf`) wins, and is
  // kept across redirect hops so a PHP proxy → CDN bounce still looks like
  // it came from the proxy page.
  if (hints?.rf) {
    headers.set('Referer', hints.rf);
  } else {
    try {
      headers.set('Referer', `${new URL(url).origin}/`);
    } catch {
      /* ignore */
    }
  }
  for (const [name, value] of parseTokenHeaders(hints?.xh)) {
    headers.set(name, value);
  }
}

async function fetchOnce(
  url: string,
  clientReq: Request,
  method: 'GET' | 'HEAD',
  deadline: number,
  kind: UpstreamKind,
  env?: Env,
  hints?: UpstreamHints,
): Promise<UpstreamResult> {
  const headers = new Headers();
  for (const h of FORWARD_REQUEST_HEADERS) {
    const v = clientReq.headers.get(h);
    if (v) headers.set(h, v);
  }
  headers.set('Accept-Encoding', 'identity');
  headers.set('User-Agent', clientReq.headers.get('user-agent') ?? 'CHRTV/1.0');
  applyClientIpForward(headers, clientReq, env);
  applyHints(headers, url, hints);

  const cf = upstreamCacheCf(kind, method, headers);

  let currentUrl = url;
  let currentMethod = method;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    // Every hop (including redirect targets) must be a safe public http(s) URL…
    if (!isSafeUpstreamUrl(currentUrl)) return { ok: false, code: ErrorCodes.UNSAFE_URL, status: 0 };
    // …on a port a Worker subrequest can actually reach. Fetching an
    // unreachable port silently lands on :80/:443 or hangs until the timeout.
    if (!isFetchablePort(currentUrl)) return { ok: false, code: ErrorCodes.UNSUPPORTED_PORT, status: 0 };

    // Shared budget across the whole redirect chain — never a fresh timer per
    // hop, so the player is never left waiting longer than the 30s policy.
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { ok: false, code: ErrorCodes.UPSTREAM_TIMEOUT, status: 0 };

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method: currentMethod,
        headers,
        redirect: 'manual',
        signal: AbortSignal.timeout(remaining),
        ...(cf ? { cf } : {}),
      });
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === 'TimeoutError';
      return { ok: false, code: timedOut ? ErrorCodes.UPSTREAM_TIMEOUT : ErrorCodes.UPSTREAM_UNREACHABLE, status: 0 };
    }

    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get('Location');
      await cancelBody(res);
      if (!location || hop === MAX_REDIRECTS) {
        return { ok: false, code: ErrorCodes.UPSTREAM_UNREACHABLE, status: res.status };
      }
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return { ok: false, code: ErrorCodes.UPSTREAM_UNREACHABLE, status: res.status };
      }
      if (res.status === 303 && currentMethod !== 'HEAD') currentMethod = 'GET';
      continue;
    }

    if (!res.ok && res.status !== 206 && res.status !== 304) {
      await cancelBody(res);
      return { ok: false, code: classifyUpstreamStatus(res.status), status: res.status };
    }
    return { ok: true, response: res, finalUrl: currentUrl };
  }
  return { ok: false, code: ErrorCodes.UPSTREAM_UNREACHABLE, status: 0 };
}

/**
 * Fetch an upstream media resource.
 * - validates URL safety + port reachability immediately before fetching
 * - follows redirects MANUALLY (max 5 hops) so every hop is checked and
 *   `finalUrl` is deterministic for relative URI resolution
 * - retries once on a fast transient failure (network / 5xx) — but only with
 *   whatever is LEFT of the shared 30s budget; a timeout is conclusive and is
 *   never retried
 * - never forwards client cookies/authorization headers upstream
 * - edge-caches successful responses briefly (status-aware, errors excluded)
 *   so concurrent viewers and rapid live polling share one upstream fetch
 */
export async function fetchUpstream(
  url: string,
  clientReq: Request,
  method: 'GET' | 'HEAD' = 'GET',
  kind: UpstreamKind = 'manifest',
  env?: Env,
  hints?: UpstreamHints,
): Promise<UpstreamResult> {
  const timeoutMs = kind === 'manifest' ? MANIFEST_TIMEOUT_MS : SEGMENT_TIMEOUT_MS;
  // One deadline for everything: redirects AND the retry share it, so total
  // player-facing wait can never exceed the policy timeout.
  const deadline = Date.now() + timeoutMs;
  const first = await fetchOnce(url, clientReq, method, deadline, kind, env, hints);
  if (first.ok || !isRetryable(first.code)) return first;
  if (deadline - Date.now() <= 0) return first;
  return fetchOnce(url, clientReq, method, deadline, kind, env, hints);
}

/** Build a passthrough media response — the body is streamed, never buffered. */
export function passthroughResponse(upstream: Response, requestId: string, isHead: boolean): Response {
  const headers = new Headers();
  for (const h of PRESERVE_RESPONSE_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) headers.set(h, v);
  }
  // Content-Length is only safe to echo when the body is not re-encoded by the
  // runtime; for HEAD there is no body to mismatch.
  const len = upstream.headers.get('content-length');
  if (len && (isHead || !upstream.headers.get('content-encoding'))) headers.set('Content-Length', len);
  headers.set('Cache-Control', 'no-store');
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, X-Request-ID');
  headers.set('X-Request-ID', requestId);
  return new Response(isHead ? null : upstream.body, { status: upstream.status, headers });
}
