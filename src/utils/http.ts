import type { ErrorCode } from '../errors/codes';

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** Reuse a well-formed client request id, otherwise mint a new one. */
export function getRequestId(req: Request): string {
  const given = req.headers.get('X-Request-ID');
  if (given && REQUEST_ID_RE.test(given)) return given;
  return crypto.randomUUID();
}

export function jsonResponse(data: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

export function errorResponse(code: ErrorCode, status: number, requestId: string): Response {
  return jsonResponse({ error: code, request_id: requestId }, status);
}

export function methodNotAllowed(allowed: string[], requestId: string): Response {
  return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED', request_id: requestId }), {
    status: 405,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      Allow: allowed.join(', '),
    },
  });
}

/** CORS preflight response for public media/playlist endpoints. */
export function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Range, X-Request-ID',
      'Access-Control-Max-Age': '86400',
    },
  });
}

/** CORS headers applied to public media/playlist responses (needed by hls.js-style web players). */
export function mediaCors(headers: Headers): void {
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, X-Request-ID');
}

/** Safe internal log line. Never pass secrets/credentials into `detail`. */
export function logEvent(requestId: string, route: string, code: string, detail = ''): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), request_id: requestId, route, code, detail }));
}
