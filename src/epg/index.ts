import type { Env } from '../types';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { corsPreflight, errorResponse, logEvent, mediaCors, methodNotAllowed } from '../utils/http';
import { ErrorCodes } from '../errors/codes';
import { requestMatchesTokenBinding, verifyToken } from '../token';
import { isTokenAuthorizationActive } from '../auth/tokenAuthorization';

/**
 * XMLTV / EPG service.
 * Cache-first: Cloudflare Cache API with a 30-minute TTL, one upstream fetch
 * per colo per TTL window. When no source is configured or every source
 * fails, a minimal-but-valid XMLTV document (channel list from D1) is served
 * so players never receive HTML.
 */

const EPG_CACHE_TTL = 30 * 60;
const EPG_FETCH_TIMEOUT_MS = 20_000;
const MAX_EPG_BYTES = 20 * 1024 * 1024;

const EPG_CACHE_KEY = new Request('https://chrtv.internal/epg/xmltv');

function xmlEscape(v: string): string {
  return v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function minimalXmltv(env: Env): Promise<string> {
  let channels: Array<{ tvg_id: string; name: string }> = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT tvg_id, name FROM channels WHERE active = 1 AND tvg_id != '' ORDER BY position ASC",
    ).all<{ tvg_id: string; name: string }>();
    channels = results;
  } catch {
    /* serve empty doc */
  }
  const body = channels
    .map((c) => `  <channel id="${xmlEscape(c.tvg_id)}"><display-name>${xmlEscape(c.name)}</display-name></channel>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE tv SYSTEM "xmltv.dtd">\n<tv generator-info-name="CHRTV">\n${body}\n</tv>\n`;
}

/** Verify a dedicated encrypted EPG token before serving cached/generated XMLTV. */
export async function handleTokenizedXmltv(
  req: Request,
  env: Env,
  requestId: string,
  rawToken: string,
): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(['GET', 'HEAD', 'OPTIONS'], requestId);
  const token = rawToken.replace(/\.xml$/i, '');
  if (rawToken !== `${token}.xml`) return errorResponse(ErrorCodes.TOKEN_INVALID, 403, requestId);
  const verdict = await verifyToken(env.SECRET_KEY, token);
  if (!verdict.ok || verdict.payload.k !== 'e') {
    const code = verdict.ok ? ErrorCodes.TOKEN_INVALID : ErrorCodes[verdict.code];
    return errorResponse(code, !verdict.ok && verdict.code === 'TOKEN_EXPIRED' ? 410 : 403, requestId);
  }
  if (!requestMatchesTokenBinding(req, verdict.payload)) {
    return errorResponse(ErrorCodes.TOKEN_BINDING_MISMATCH, 403, requestId);
  }
  if (!(await isTokenAuthorizationActive(env, verdict.payload))) {
    return errorResponse(ErrorCodes.AUTH_DISABLED, 403, requestId);
  }
  const response = await handleXmltv(req, env, requestId);
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'private, max-age=1800');
  headers.set('Referrer-Policy', 'no-referrer');
  mediaCors(headers);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** Internal XMLTV producer; public routing should go through an EPG token. */
export async function handleXmltv(req: Request, env: Env, requestId: string): Promise<Response> {
  const isHead = req.method === 'HEAD';

  // 1. Edge cache
  try {
    const cached = await caches.default.match(EPG_CACHE_KEY);
    if (cached) {
      const headers = new Headers(cached.headers);
      headers.set('X-Request-ID', requestId);
      return new Response(isHead ? null : cached.body, { status: 200, headers });
    }
  } catch {
    /* cache unavailable — fall through */
  }

  // 2. Upstream source (if configured)
  const source = (env.EPG_URL ?? '').trim();
  if (source && isSafeUpstreamUrl(source)) {
    try {
      const res = await fetch(source, {
        signal: AbortSignal.timeout(EPG_FETCH_TIMEOUT_MS),
        headers: { 'User-Agent': 'CHRTV-epg/1.0' },
      });
      if (res.ok) {
        const text = await res.text();
        if (text.length <= MAX_EPG_BYTES && text.includes('<tv')) {
          const response = new Response(text, {
            headers: {
              'Content-Type': 'application/xml; charset=utf-8',
              'Cache-Control': `public, max-age=${EPG_CACHE_TTL}`,
            },
          });
          try {
            await caches.default.put(EPG_CACHE_KEY, response.clone());
          } catch {
            /* ignore */
          }
          const headers = new Headers(response.headers);
          headers.set('X-Request-ID', requestId);
          return new Response(isHead ? null : text, { status: 200, headers });
        }
      }
      logEvent(requestId, '/xmltv.php', 'EPG_SOURCE_INVALID', `status=${res.status}`);
    } catch {
      logEvent(requestId, '/xmltv.php', 'EPG_SOURCE_UNREACHABLE');
    }
  }

  // 3. Fallback: minimal valid XMLTV
  const fallback = await minimalXmltv(env);
  return new Response(isHead ? null : fallback, {
    status: 200,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
      'X-Request-ID': requestId,
    },
  });
}
