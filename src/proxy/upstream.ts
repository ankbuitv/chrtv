import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';
import { ErrorCodes, type ErrorCode } from '../errors/codes';

/**
 * Operator policy: an upstream is only declared dead after **30s of silence**.
 * Slow relays (e.g. devda.undo.it bouncing to the real CDN) routinely take
 * 10-25s to first byte — slow to tune in, but perfectly watchable. Cutting
 * them off at 6-8s tripped the circuit breaker on healthy channels, which is
 * exactly how "kênh hệ thống xem bình thường mà bị báo offline" happens.
 * Kept as two constants so operators can still tune manifest vs segment
 * separately, but both default to the same 30s ceiling. (Player-side fetch
 * waits don't count against Workers CPU time, only wall clock.)
 */
const MANIFEST_TIMEOUT_MS = 30_000;
const SEGMENT_TIMEOUT_MS = 30_000;

/**
 * Request headers forwarded to the upstream. Auth/cookies are never forwarded.
 * `accept-encoding` is deliberately NOT forwarded: the Workers runtime
 * transparently decodes compressed bodies, which then no longer match the
 * upstream `Content-Length` and makes players see truncated segments.
 */
const FORWARD_REQUEST_HEADERS = ['range', 'accept', 'if-none-match', 'if-modified-since'];

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
 * it would just stretch "quá 30s mới offline" into 60s before the player ever
 * sees the fallback.
 */
function isRetryable(code: ErrorCode): boolean {
  return code === ErrorCodes.UPSTREAM_UNREACHABLE || code === ErrorCodes.UPSTREAM_5XX;
}

async function fetchOnce(
  url: string,
  clientReq: Request,
  method: 'GET' | 'HEAD',
  timeoutMs: number,
): Promise<UpstreamResult> {
  const headers = new Headers();
  for (const h of FORWARD_REQUEST_HEADERS) {
    const v = clientReq.headers.get(h);
    if (v) headers.set(h, v);
  }
  headers.set('Accept-Encoding', 'identity');
  headers.set('User-Agent', clientReq.headers.get('user-agent') ?? 'CHRTV/1.0');

  let currentUrl = url;
  let currentMethod = method;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    // Every hop (including redirect targets) must be a safe public http(s) URL…
    if (!isSafeUpstreamUrl(currentUrl)) return { ok: false, code: ErrorCodes.UNSAFE_URL, status: 0 };
    // …on a port a Worker subrequest can actually reach. Fetching an
    // unreachable port silently lands on :80/:443 or hangs until the timeout.
    if (!isFetchablePort(currentUrl)) return { ok: false, code: ErrorCodes.UNSUPPORTED_PORT, status: 0 };

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method: currentMethod,
        headers,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
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
 * - retries once on a fast transient failure (network / 5xx); a 30s timeout
 *   is conclusive and is never retried
 * - never forwards client cookies/authorization headers upstream
 */
export async function fetchUpstream(
  url: string,
  clientReq: Request,
  method: 'GET' | 'HEAD' = 'GET',
  kind: UpstreamKind = 'manifest',
): Promise<UpstreamResult> {
  const timeoutMs = kind === 'manifest' ? MANIFEST_TIMEOUT_MS : SEGMENT_TIMEOUT_MS;
  const first = await fetchOnce(url, clientReq, method, timeoutMs);
  if (first.ok || !isRetryable(first.code)) return first;
  return fetchOnce(url, clientReq, method, timeoutMs);
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
