import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { ErrorCodes, type ErrorCode } from '../errors/codes';

const UPSTREAM_TIMEOUT_MS = 15_000;

/** Request headers forwarded to the upstream. Auth/cookies are never forwarded. */
const FORWARD_REQUEST_HEADERS = ['range', 'accept', 'accept-encoding', 'if-none-match', 'if-modified-since'];

/** Response headers preserved from the upstream. */
const PRESERVE_RESPONSE_HEADERS = [
  'content-type',
  'content-length',
  'content-range',
  'accept-ranges',
  'etag',
  'last-modified',
  'date',
];

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
 * Fetch an upstream media resource.
 * - validates URL safety immediately before fetching (defense in depth)
 * - follows redirects MANUALLY (max 5 hops) so every hop is SSRF-checked and
 *   `finalUrl` is deterministic for relative URI resolution
 * - never forwards client cookies/authorization headers upstream
 */
export async function fetchUpstream(url: string, clientReq: Request, method: 'GET' | 'HEAD' = 'GET'): Promise<UpstreamResult> {
  const headers = new Headers();
  for (const h of FORWARD_REQUEST_HEADERS) {
    const v = clientReq.headers.get(h);
    if (v) headers.set(h, v);
  }
  headers.set('User-Agent', clientReq.headers.get('user-agent') ?? 'CHRTV/1.0');

  let currentUrl = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    // Every hop (including redirect targets) must be a safe public http(s) URL.
    if (!isSafeUpstreamUrl(currentUrl)) return { ok: false, code: ErrorCodes.UNSAFE_URL, status: 0 };

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method,
        headers,
        redirect: 'manual',
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
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
      if (res.status === 303 && method !== 'HEAD') method = 'GET';
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

/** Build a passthrough media response — the body is streamed, never buffered. */
export function passthroughResponse(upstream: Response, requestId: string, isHead: boolean): Response {
  const headers = new Headers();
  for (const h of PRESERVE_RESPONSE_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) headers.set(h, v);
  }
  headers.set('Cache-Control', 'no-store');
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, X-Request-ID');
  headers.set('X-Request-ID', requestId);
  return new Response(isHead ? null : upstream.body, { status: upstream.status, headers });
}
