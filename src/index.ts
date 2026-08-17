import type { Env } from './types';
import { getRequestId, errorResponse, methodNotAllowed, corsPreflight, logEvent } from './utils/http';
import { ErrorCodes } from './errors/codes';
import { buildPlaylist, playlistResponse } from './playlist/output';
import { syncPlaylist } from './playlist/sync';
import { runScheduledHealthCheck } from './playlist/health';
import { handleHlsManifest, handleSegment } from './proxy/handlers';
import { handlePlayerApi, handlePanelApi, handleGetPhp, handleXtreamLive, handleXtreamXmltv } from './xtream';
import { handleTokenizedXmltv } from './epg';
import { handleAdmin } from './admin';
import { authenticateAccessKey } from './auth';
import { handlePrivateLogin } from './auth/privateLogin';
import { handleAccountApi, handleLoginApi, handleSessionPlaylist } from './auth/loginApi';
import { recordAuthEvent } from './auth/audit';
import {
  banClient,
  honeypotEnabled,
  isClientBanned,
  isHoneypotPath,
  securityBanSeconds,
  shouldBanHoneypotRequest,
} from './security/honeypot';
import { landingPage, notFoundPage } from './pages';
import { adminDashboardPage, loginPortalPage, portalScript } from './pages/portals';
import { getSettings } from './db/settings';
import { requestTokenBinding } from './token';

/**
 * CHRTV — Cloud IPTV Gateway (Cloudflare Workers + D1)
 *
 * Public routes
 *   GET  /                      landing page
 *   GET  /login, /admin         browser portals
 *   GET  /tv.m3u, /xem.m3u      public-configurable main playlist
 *   POST /api/login             opaque M3U session exchange
 *   GET  /p/{session}.m3u       revocable password-free user playlist
 *   GET  /lg/{user}?{pass}.m3u  legacy private D1-authenticated M3U
 *   GET  /epg/{token}.xml       identity-bound XMLTV EPG
 *   GET  /hls/{token}.m3u8      HLS manifest proxy (rewritten, tokenized)
 *   GET  /seg/{token}[.ext]     media/key/subtitle passthrough
 *   GET  /player_api.php        authenticated Xtream Codes API
 *   GET  /get.php               authenticated Xtream M3U download
 *   GET  /live/{u}/{p}/{id}     authenticated Xtream live exchange
 *   GET  /xmltv.php             authenticated Xtream EPG exchange
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

  let accessKeyId: number | undefined;
  let userId: number | undefined;
  let username: string | undefined;
  let playlistExpiry: number | null | undefined;
  if (key) {
    // A key was supplied: always validate it (and register the device by MAC).
    const auth = await authenticateAccessKey(env, key, mac, req.headers.get('user-agent') ?? '');
    if (!auth.ok) {
      logEvent(requestId, url.pathname, auth.code);
      await recordAuthEvent(req, env, {
        eventType: 'access_key',
        route: url.pathname,
        outcome: 'failure',
      });
      return errorResponse(auth.code, auth.status, requestId);
    }
    accessKeyId = auth.value.id;
    userId = auth.value.user_id ?? undefined;
    username = auth.value.username || undefined;
    playlistExpiry = auth.value.expires_at;
    await recordAuthEvent(req, env, {
      userId: auth.value.user_id,
      username: auth.value.username,
      eventType: 'access_key',
      route: url.pathname,
      outcome: 'success',
    });
  } else if (!publicPlaylist) {
    logEvent(requestId, url.pathname, ErrorCodes.KEY_INVALID, 'key required');
    await recordAuthEvent(req, env, {
      eventType: 'playlist',
      route: url.pathname,
      outcome: 'failure',
    });
    return errorResponse(ErrorCodes.KEY_INVALID, 401, requestId);
  }

  // The encrypted channel tokens are personalized by every trustworthy identity
  // available here. IP is observed by Cloudflare and strictly enforced on
  // subsequent media requests; MAC is client-declared and normalized; user/key
  // ids come only from authenticated D1 records.
  const binding = requestTokenBinding(req, { rawMac: mac, userId, accessKeyId }, env.TOKEN_BINDING);
  const body = await buildPlaylist(env, url.origin, binding, playlistExpiry);
  await recordAuthEvent(req, env, {
    userId,
    username,
    eventType: 'playlist',
    route: url.pathname,
    outcome: 'success',
  });
  return playlistResponse(body, requestId, req.method === 'HEAD');
}

async function route(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // ---- user/admin browser portals (no sensitive data is embedded in HTML) ----
  if (path === '/login' && (req.method === 'GET' || req.method === 'HEAD')) return loginPortalPage();
  if (path === '/admin' && (req.method === 'GET' || req.method === 'HEAD')) return adminDashboardPage();
  if (path === '/ui/login.js' && req.method === 'GET') return portalScript('login');
  if (path === '/ui/admin.js' && req.method === 'GET') return portalScript('admin');

  // ---- safe credential exchange + user session self-service ----
  if (path === '/api/login') return handleLoginApi(req, env, requestId);
  if (path === '/api/account' || path.startsWith('/api/account/')) {
    const subPath = path.slice('/api/account'.length).replace(/^\//, '');
    return handleAccountApi(req, env, requestId, subPath);
  }

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
  if (path.startsWith('/lg/')) {
    if (!['GET', 'HEAD'].includes(req.method)) return methodNotAllowed(['GET', 'HEAD'], requestId);
    return handlePrivateLogin(req, env, requestId);
  }
  if (path.startsWith('/p/')) return handleSessionPlaylist(req, env, requestId, path.slice('/p/'.length));

  // ---- HLS proxy ----
  if (path.startsWith('/hls/')) return handleHlsManifest(req, env, requestId, path.slice('/hls/'.length));
  if (path.startsWith('/seg/')) return handleSegment(req, env, requestId, path.slice('/seg/'.length));

  // ---- Xtream Codes ----
  if (path === '/player_api.php' || path === '/player-api.php' || path === '/playerapi.php') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (req.method !== 'GET' && req.method !== 'POST' && req.method !== 'HEAD') {
      return methodNotAllowed(['GET', 'POST', 'HEAD', 'OPTIONS'], requestId);
    }
    return handlePlayerApi(req, env, requestId);
  }
  if (path === '/panel_api.php') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (req.method !== 'GET' && req.method !== 'POST' && req.method !== 'HEAD') {
      return methodNotAllowed(['GET', 'POST', 'HEAD', 'OPTIONS'], requestId);
    }
    return handlePanelApi(req, env, requestId);
  }
  if (path === '/get.php' || path === '/getphp' || path === '/enigma2.php') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (req.method === 'POST') return handleGetPhp(req, env, requestId);
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleGetPhp(req, env, requestId);
  }
  // /live/{u}/{p}/{id} plus the movie/series prefixes clients probe on login,
  // and the bare /{u}/{p}/{numeric id}(.m3u8|.ts) form some clients build when
  // the portal URL has no /live prefix (kept strict so it cannot shadow other
  // routes: the stream id must be numeric).
  const liveMatch =
    path.match(/^\/(?:live|movie|series)\/([^/]+)\/([^/]+)\/([^/]+)$/) ??
    path.match(/^\/([^/]+)\/([^/]+)\/(\d+(?:\.(?:m3u8|ts))?)$/);
  if (liveMatch) {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleXtreamLive(req, env, requestId, liveMatch[1]!, liveMatch[2]!, liveMatch[3]!);
  }

  // ---- EPG: playlists use /epg/{token}.xml; legacy Xtream credentials redirect there ----
  if (path.startsWith('/epg/')) return handleTokenizedXmltv(req, env, requestId, path.slice('/epg/'.length));
  if (path === '/xmltv.php' || path === '/epg.xml') {
    if (req.method === 'OPTIONS') return corsPreflight();
    if (!STREAM_METHODS.includes(req.method)) return methodNotAllowed(STREAM_METHODS, requestId);
    return handleXtreamXmltv(req, env, requestId);
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
  const now = Math.floor(Date.now() / 1000);
  const cutoffDevices = now - 90 * 24 * 3600;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM stream_failures WHERE created_at < ?').bind(cutoffFailures),
    env.DB.prepare('DELETE FROM sync_logs WHERE started_at < ?').bind(cutoffLogs),
    env.DB.prepare("DELETE FROM devices WHERE last_seen < ? AND status != 'active'").bind(cutoffDevices),
    env.DB.prepare('DELETE FROM security_bans WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM security_login_failures WHERE last_failed <= ?').bind(now - 24 * 3600),
    env.DB.prepare('DELETE FROM auth_events WHERE created_at < ?').bind(now - 30 * 24 * 3600),
    env.DB.prepare("UPDATE user_sessions SET status = 'expired' WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM user_sessions WHERE status != 'active' AND last_seen < ?").bind(now - 90 * 24 * 3600),
    // Drop health rows for channels that have since been deactivated/removed.
    env.DB.prepare('DELETE FROM channel_health WHERE channel_id IN (SELECT id FROM channels WHERE active = 0)'),
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
      const path = new URL(req.url).pathname;
      // A trap looks like an ordinary missing page, but immediately promotes
      // the Cloudflare-observed source IP to a durable one-day ban.
      if (honeypotEnabled(env) && isHoneypotPath(path)) {
        if (shouldBanHoneypotRequest(req)) {
          await banClient(req, env, 'honeypot');
          logEvent(requestId, 'honeypot', 'SECURITY_TRAP');
        } else {
          logEvent(requestId, 'honeypot', 'SECURITY_TRAP_CROSS_SITE');
        }
        return notFoundPage(requestId);
      }
      if (await isClientBanned(req, env)) {
        logEvent(requestId, 'security', ErrorCodes.SECURITY_BANNED);
        const blocked = errorResponse(ErrorCodes.SECURITY_BANNED, 403, requestId);
        blocked.headers.set('Retry-After', String(securityBanSeconds(env)));
        blocked.headers.set('X-Request-ID', requestId);
        return blocked;
      }

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
    // Channel health sweep — bounded batch of the oldest-checked channels.
    if (event.cron === '*/10 * * * *') {
      ctx.waitUntil(runScheduledHealthCheck(env));
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
