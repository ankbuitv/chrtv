import type { Env } from './types';
import { getRequestId, errorResponse, methodNotAllowed, corsPreflight, logEvent } from './utils/http';
import { ErrorCodes } from './errors/codes';
import { buildPlaylist, playlistResponse } from './playlist/output';
import { syncPlaylist } from './playlist/sync';
import { handleHlsManifest, handleSegment } from './proxy/handlers';
import { handlePlayerApi, handleGetPhp, handleXtreamLive } from './xtream';
import { handleXmltv } from './epg';
import { handleAdmin } from './admin';
import { authenticateAccessKey } from './auth';
import { landingPage, notFoundPage } from './pages';
import { getSettings } from './db/settings';

/**
 * CHRTV — Cloud IPTV Gateway (Cloudflare Workers + D1)
 *
 * Public routes
 *   GET  /                      landing page
 *   GET  /tv.m3u                main playlist (zero-config UX; see below)
 *   GET  /xem.m3u               alias of /tv.m3u
 *   GET  /hls/{token}.m3u8      HLS manifest proxy (rewritten, tokenized)
 *   GET  /seg/{token}[.ext]     media passthrough (ts/m4s/aac/mp4/key/vtt/…)
 *   GET  /player_api.php        Xtream Codes API   (also /player-api.php)
 *   GET  /get.php               Xtream M3U download
 *   GET  /live/{u}/{p}/{id}     Xtream live stream
 *   GET  /xmltv.php             XMLTV EPG (also /epg.xml)
 *   *    /api/admin/*           admin API (Bearer ADMIN_TOKEN)
 *
 * /tv.m3u UX: the endpoint works as-is (PUBLIC_PLAYLIST=true, the default).
 * The playlist itself contains only CHRTV-encrypted, expiring channel tokens,
 * so this never becomes an open proxy — the worker only ever fetches
 * upstreams from its own D1 channel table or from tokens it minted itself.
 * Operators can set PUBLIC_PLAYLIST=false to require an access key
 * (?key=chr_…&mac=AA:BB:…), which also enables MAC device tracking.
 */

const STREAM_METHODS = ['GET', 'HEAD', 'OPTIONS'];

async function handlePlaylistRoute(req: Request, env: Env, requestId: string): Promise<Response> {
  if (req.method === 'OPTIONS') return corsPreflight();
  if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);

  const url = new URL(req.url);
  const publicPlaylist = (env.PUBLIC_PLAYLIST ?? 'true').toLowerCase() !== 'false';
  const key = url.searchParams.get('key') ?? url.searchParams.get('access_key');
  const mac = url.searchParams.get('mac');

  if (key) {
    // A key was supplied: always validate it (and register the device by MAC).
    const auth = await authenticateAccessKey(env, key, mac, req.headers.get('user-agent') ?? '');
    if (!auth.ok) {
      logEvent(requestId, url.pathname, auth.code);
      return errorResponse(auth.code, auth.status, requestId);
    }
  } else if (!publicPlaylist) {
    logEvent(requestId, url.pathname, ErrorCodes.KEY_INVALID, 'key required');
    return errorResponse(ErrorCodes.KEY_INVALID, 401, requestId);
  }

  const body = await buildPlaylist(env, url.origin);
  return playlistResponse(body, requestId, req.method === 'HEAD');
}

async function route(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // ---- landing ----
  if (path === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    try {
      const s = await getSettings(env.DB, ['sync_status', 'channel_count', 'last_sync']);
      return landingPage({
        syncStatus: s['sync_status'] ?? 'never',
        channelCount: s['channel_count'] ?? '0',
        lastSync: s['last_sync'] ?? '',
      });
    } catch {
      return landingPage({ syncStatus: 'never', channelCount: '0', lastSync: '' });
    }
  }

  // ---- playlists ----
  if (path === '/tv.m3u' || path === '/xem.m3u') return handlePlaylistRoute(req, env, requestId);

  // ---- HLS proxy ----
  if (path.startsWith('/hls/')) return handleHlsManifest(req, env, requestId, path.slice('/hls/'.length));
  if (path.startsWith('/seg/')) return handleSegment(req, env, requestId, path.slice('/seg/'.length));

  // ---- Xtream Codes ----
  if (path === '/player_api.php' || path === '/player-api.php' || path === '/panel_api.php') {
    if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(['GET', 'POST'], requestId);
    return handlePlayerApi(req, env, requestId);
  }
  if (path === '/get.php') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleGetPhp(req, env, requestId);
  }
  const liveMatch = path.match(/^\/live\/([^/]+)\/([^/]+)\/([^/]+)$/);
  if (liveMatch) {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleXtreamLive(req, env, requestId, liveMatch[1]!, liveMatch[2]!, liveMatch[3]!);
  }

  // ---- EPG ----
  if (path === '/xmltv.php' || path === '/epg.xml') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleXmltv(req, env, requestId);
  }

  // ---- Admin ----
  if (path === '/api/admin' || path.startsWith('/api/admin/')) {
    const subPath = path.slice('/api/admin'.length).replace(/^\//, '');
    return handleAdmin(req, env, requestId, subPath);
  }

  // ---- health ----
  if (path === '/healthz') {
    return new Response(JSON.stringify({ ok: true, service: 'CHRTV' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return notFoundPage(requestId);
}

async function cleanup(env: Env): Promise<void> {
  const cutoffFailures = Math.floor(Date.now() / 1000) - 7 * 24 * 3600;
  const cutoffLogs = Math.floor(Date.now() / 1000) - 30 * 24 * 3600;
  const cutoffDevices = Math.floor(Date.now() / 1000) - 90 * 24 * 3600;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM stream_failures WHERE created_at < ?').bind(cutoffFailures),
    env.DB.prepare('DELETE FROM sync_logs WHERE started_at < ?').bind(cutoffLogs),
    env.DB.prepare("DELETE FROM devices WHERE last_seen < ? AND status != 'active'").bind(cutoffDevices),
  ]);
}

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const requestId = getRequestId(req);
    if (!env.SECRET_KEY || env.SECRET_KEY.length < 16) {
      logEvent(requestId, new URL(req.url).pathname, 'CONFIG_ERROR', 'SECRET_KEY missing or too short');
      return errorResponse(ErrorCodes.CONFIG_ERROR, 500, requestId);
    }
    try {
      const res = await route(req, env, requestId);
      if (!res.headers.has('X-Request-ID')) {
        const headers = new Headers(res.headers);
        headers.set('X-Request-ID', requestId);
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
      }
      return res;
    } catch (err) {
      logEvent(requestId, new URL(req.url).pathname, 'UNHANDLED', err instanceof Error ? err.message : 'unknown');
      return errorResponse(ErrorCodes.INTERNAL_ERROR, 500, requestId);
    }
  },

  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    if (event.cron === '23 3 * * *') {
      ctx.waitUntil(cleanup(env));
      return;
    }
    // Playlist sync — the settings-based lock makes overlapping runs safe.
    ctx.waitUntil(
      syncPlaylist(env, 'cron').then((r) => {
        console.log(JSON.stringify({ ts: new Date().toISOString(), cron: event.cron, sync: r.status, error: r.error ?? '' }));
      }),
    );
  },
} satisfies ExportedHandler<Env>;
