import type { Env, ChannelRow, UserRow } from '../types';
import { authenticateUser, type AuthResult } from '../auth';
import { recordAuthEvent, type AuthEventType } from '../auth/audit';
import { clearLoginFailures, recordLoginFailure } from '../security/honeypot';
import { listActiveChannels, listCategories, getChannelByXtreamId } from '../db/channels';
import { createToken, DEFAULT_MANIFEST_TTL, requestTokenBinding } from '../token';
import { buildPlaylist, playlistResponse } from '../playlist/output';
import { jsonResponse, errorResponse, logEvent } from '../utils/http';
import { ErrorCodes } from '../errors/codes';

/**
 * Xtream Codes compatibility layer.
 * Implements what real IPTV clients (TiviMate, IPTV Smarters, OTT Navigator)
 * actually call:
 *   /player_api.php (auth, get_live_categories, get_live_streams, ...)
 *   /panel_api.php  (legacy all-in-one payload)
 *   /get.php        (M3U download)
 *   /live/{user}/{pass}/{stream_id}.m3u8
 *   /xmltv.php      (handled by the EPG module)
 * Stubbed-empty responses for VOD/series actions keep clients happy.
 * Passwords are never echoed back except in the user_info block, which the
 * Xtream protocol requires for client compatibility (it echoes the password
 * the client itself supplied — never another user's secret).
 */

/** Credentials as sent by clients — query string, form body, JSON body or Basic auth. */
export interface XtreamCredentials {
  username: string;
  password: string;
  params: URLSearchParams;
}

function decodeBasicAuth(header: string | null): { username: string; password: string } | null {
  if (!header) return null;
  const m = header.match(/^Basic\s+(.+)$/i);
  if (!m || !m[1]) return null;
  try {
    const decoded = atob(m[1].trim());
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}

/**
 * Extract credentials + action params from a request.
 *
 * Different clients send them in completely different ways:
 *   - TiviMate / OTT Navigator: query string
 *   - IPTV Smarters: POST form body, sometimes a POST JSON body
 *   - a few web players: HTTP Basic auth
 * Previously only the query string (and form bodies) were read, so a client
 * POSTing JSON authenticated as an empty user and got `auth: 0` — i.e. "login
 * failed" even though the gateway is in public mode.
 */
export async function readCredentials(req: Request): Promise<XtreamCredentials> {
  const url = new URL(req.url);
  const params = new URLSearchParams(url.search);

  if (req.method === 'POST') {
    const ctype = (req.headers.get('content-type') ?? '').toLowerCase();
    try {
      if (ctype.includes('json')) {
        const body = (await req.json()) as Record<string, unknown> | null;
        if (body && typeof body === 'object') {
          for (const [k, v] of Object.entries(body)) {
            if ((typeof v === 'string' || typeof v === 'number') && !params.has(k)) params.set(k, String(v));
          }
        }
      } else {
        // form-urlencoded, multipart, or an unlabelled body — formData() copes
        // with the first two and throws (harmlessly) otherwise.
        const form = await req.formData();
        for (const [k, v] of form.entries()) {
          if (typeof v === 'string' && !params.has(k)) params.set(k, v);
        }
      }
    } catch {
      /* fall back to query params */
    }
  }

  let username = params.get('username') ?? '';
  let password = params.get('password') ?? '';
  if (!username || !password) {
    const basic = decodeBasicAuth(req.headers.get('Authorization'));
    if (basic) {
      username = username || basic.username;
      password = password || basic.password;
    }
  }
  return { username, password, params };
}

/**
 * Xtream always requires a real D1 user. The intentionally public /tv.m3u is
 * the sole no-credential playlist exception; public mode must not silently turn
 * arbitrary Xtream usernames into guest accounts.
 */
async function authenticateXtreamRequest(
  req: Request,
  env: Env,
  username: string,
  password: string,
  route: string,
  eventType: AuthEventType = 'xtream',
  auditSuccess = true,
): Promise<AuthResult<UserRow>> {
  const auth = await authenticateUser(env, username, password);
  if (!auth.ok) {
    const banned = await recordLoginFailure(req, env);
    await recordAuthEvent(req, env, {
      username,
      eventType,
      route,
      outcome: banned ? 'blocked' : 'failure',
    });
    return auth;
  }
  await clearLoginFailures(req, env);
  if (auditSuccess) {
    await recordAuthEvent(req, env, {
      userId: auth.value.id,
      username: auth.value.username,
      eventType,
      route,
      outcome: 'success',
    });
  }
  return auth;
}

function xtreamUserInfo(username: string, password: string, expiresAt: number | null, maxConnections: number) {
  return {
    user_info: {
      username,
      password, // echo of client-supplied credential (Xtream protocol requirement)
      message: 'Welcome to CHRTV',
      auth: 1,
      status: 'Active',
      exp_date: expiresAt ? String(expiresAt) : null,
      is_trial: '0',
      active_cons: '0',
      created_at: '0',
      max_connections: String(maxConnections),
      // Clients pick their stream format from this list. CHRTV proxies HLS, so
      // m3u8 is first; `ts` stays listed because several clients refuse to log
      // in when it is missing (they treat the account as "no output format").
      allowed_output_formats: ['m3u8', 'ts'],
    },
  };
}

function serverInfo(origin: string) {
  const url = new URL(origin);
  const isHttps = url.protocol === 'https:';
  const port = url.port || (isHttps ? '443' : '80');
  return {
    server_info: {
      xui: false,
      version: '1.0.0',
      revision: 1,
      url: url.hostname,
      port: isHttps ? '80' : port,
      https_port: isHttps ? port : '443',
      server_protocol: url.protocol.replace(':', ''),
      rtmp_port: '0',
      timezone: 'UTC',
      timestamp_now: Math.floor(Date.now() / 1000),
      time_now: new Date().toISOString().slice(0, 19).replace('T', ' '),
    },
  };
}

function liveStreamEntry(ch: ChannelRow, i: number, directSource = '') {
  return {
    num: i + 1,
    name: ch.name,
    stream_type: 'live',
    stream_id: ch.xtream_id,
    stream_icon: ch.tvg_logo,
    epg_channel_id: ch.tvg_id || null,
    added: '0',
    category_id: String(ch.category_id ?? 0),
    custom_sid: '',
    tv_archive: 0,
    direct_source: directSource,
    tv_archive_duration: 0,
  };
}

function boundedTokenExpiry(issued: number, accountExpiry: number | null): number {
  const configured = issued + DEFAULT_MANIFEST_TTL;
  return accountExpiry !== null && accountExpiry > 0 ? Math.min(configured, accountExpiry) : configured;
}

async function tokenizedLiveEntries(
  channels: ChannelRow[],
  env: Env,
  req: Request,
  origin: string,
  userId: number,
  accountExpiry: number | null,
): Promise<ReturnType<typeof liveStreamEntry>[]> {
  const issued = Math.floor(Date.now() / 1000);
  const expires = boundedTokenExpiry(issued, accountExpiry);
  const binding = requestTokenBinding(req, { userId }, env.TOKEN_BINDING);
  return Promise.all(
    channels.map(async (channel, index) => {
      const token = await createToken(env.SECRET_KEY, {
        u: channel.url,
        iat: issued,
        exp: expires,
        k: 'm',
        c: channel.id,
        ...binding,
      });
      return liveStreamEntry(channel, index, `${origin}/hls/${token}.m3u8`);
    }),
  );
}

export async function handlePlayerApi(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const { username, password, params } = await readCredentials(req);
  const action = params.get('action') ?? '';

  const auth = await authenticateXtreamRequest(req, env, username, password, '/player_api.php', 'xtream', action === '');
  if (!auth.ok) {
    logEvent(requestId, '/player_api.php', auth.code);
    // Xtream clients expect a 200 + auth:0 body on bad credentials.
    return jsonResponse({ user_info: { auth: 0, status: 'Disabled' } }, 200);
  }
  const user = auth.value;
  const origin = url.origin;
  const info = { ...xtreamUserInfo(username, password, user.expires_at, user.max_connections), ...serverInfo(origin) };

  switch (action) {
    case '': // handshake
      return jsonResponse(info);
    case 'get_live_categories': {
      const cats = await listCategories(env.DB);
      return jsonResponse(cats.map((c) => ({ category_id: String(c.id), category_name: c.name, parent_id: 0 })));
    }
    case 'get_live_streams': {
      const channels = await listActiveChannels(env.DB);
      const catFilter = params.get('category_id');
      const filtered = catFilter ? channels.filter((c) => String(c.category_id ?? 0) === catFilter) : channels;
      return jsonResponse(await tokenizedLiveEntries(filtered, env, req, origin, user.id, user.expires_at));
    }
    case 'get_vod_categories':
    case 'get_series_categories':
    case 'get_vod_streams':
    case 'get_series':
      return jsonResponse([]);
    case 'get_vod_info':
    case 'get_series_info':
      return jsonResponse({});
    case 'get_short_epg':
    case 'get_simple_data_table':
      return jsonResponse({ epg_listings: [] });
    case 'get_account_info':
    case 'get_profile':
      return jsonResponse(info);
    default:
      return jsonResponse(info);
  }
}

/**
 * /panel_api.php — legacy all-in-one payload some older clients still use to
 * log in. It must contain user_info + server_info + the channel/category maps.
 */
export async function handlePanelApi(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const { username, password } = await readCredentials(req);
  const auth = await authenticateXtreamRequest(req, env, username, password, '/panel_api.php');
  if (!auth.ok) {
    logEvent(requestId, '/panel_api.php', auth.code);
    return jsonResponse({ user_info: { auth: 0, status: 'Disabled' } }, 200);
  }
  const user = auth.value;
  const [channels, cats] = await Promise.all([listActiveChannels(env.DB), listCategories(env.DB)]);
  const categories: Record<string, string> = {};
  for (const c of cats) categories[String(c.id)] = c.name;
  const entries = await tokenizedLiveEntries(channels, env, req, url.origin, user.id, user.expires_at);

  return jsonResponse({
    ...xtreamUserInfo(username, password, user.expires_at, user.max_connections),
    ...serverInfo(url.origin),
    categories: { live: categories, movie: {}, series: {} },
    available_channels: Object.fromEntries(entries.map((entry) => [String(entry.stream_id), entry])),
  });
}

/** /get.php?username=..&password=..&type=m3u_plus — full M3U download. */
export async function handleGetPhp(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const { username, password, params } = await readCredentials(req);
  const auth = await authenticateXtreamRequest(req, env, username, password, '/get.php', 'playlist');
  if (!auth.ok) {
    logEvent(requestId, '/get.php', auth.code);
    return errorResponse(auth.code, auth.status, requestId);
  }
  const binding = requestTokenBinding(
    req,
    {
      rawMac: params.get('mac'),
      userId: auth.value.id,
    },
    env.TOKEN_BINDING,
  );
  const body = await buildPlaylist(env, url.origin, binding, auth.value.expires_at);
  return playlistResponse(body, requestId, req.method === 'HEAD');
}

/** /live/{username}/{password}/{stream_id}(.m3u8) — Xtream live stream entry. */
export async function handleXtreamLive(
  req: Request,
  env: Env,
  requestId: string,
  username: string,
  password: string,
  streamRef: string,
): Promise<Response> {
  let user = username;
  let pass = password;
  try {
    user = decodeURIComponent(username);
    pass = decodeURIComponent(password);
  } catch {
    /* keep raw values on malformed percent-encoding */
  }
  const auth = await authenticateXtreamRequest(req, env, user, pass, '/live');
  if (!auth.ok) {
    logEvent(requestId, '/live', auth.code);
    return errorResponse(auth.code, auth.status, requestId);
  }
  const idPart = streamRef.replace(/\.(m3u8|ts)$/i, '');
  const xtreamId = Number(idPart);
  if (!Number.isInteger(xtreamId)) return errorResponse(ErrorCodes.NOT_FOUND, 404, requestId);
  const channel = await getChannelByXtreamId(env.DB, xtreamId);
  if (!channel) return errorResponse(ErrorCodes.NOT_FOUND, 404, requestId);

  const now = Math.floor(Date.now() / 1000);
  const binding = requestTokenBinding(
    req,
    {
      rawMac: new URL(req.url).searchParams.get('mac'),
      userId: auth.value.id,
    },
    env.TOKEN_BINDING,
  );
  const token = await createToken(env.SECRET_KEY, {
    u: channel.url,
    iat: now,
    exp: boundedTokenExpiry(now, auth.value.expires_at),
    k: 'm',
    c: channel.id,
    ...binding,
  });
  // Legacy credential URLs remain accepted for Xtream compatibility, but they
  // never serve media directly: the client is moved onto the opaque token URL.
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${new URL(req.url).origin}/hls/${token}.m3u8`,
      'Cache-Control': 'private, no-store',
      'Referrer-Policy': 'no-referrer',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
    },
  });
}

/** Legacy Xtream XMLTV credentials are exchanged for a dedicated EPG token. */
export async function handleXtreamXmltv(req: Request, env: Env, requestId: string): Promise<Response> {
  const { username, password, params } = await readCredentials(req);
  const auth = await authenticateXtreamRequest(req, env, username, password, '/xmltv.php', 'xtream');
  if (!auth.ok) return errorResponse(auth.code, auth.status, requestId);
  const issued = Math.floor(Date.now() / 1000);
  const binding = requestTokenBinding(req, { rawMac: params.get('mac'), userId: auth.value.id }, env.TOKEN_BINDING);
  const token = await createToken(env.SECRET_KEY, {
    u: 'https://epg-token.chrtv.invalid/xmltv.xml',
    iat: issued,
    exp: boundedTokenExpiry(issued, auth.value.expires_at),
    k: 'e',
    ...binding,
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${new URL(req.url).origin}/epg/${token}.xml`,
      'Cache-Control': 'private, no-store',
      'Referrer-Policy': 'no-referrer',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
    },
  });
}
