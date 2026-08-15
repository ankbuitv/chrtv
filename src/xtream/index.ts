import type { Env, ChannelRow, UserRow } from '../types';
import { authenticateUser, type AuthResult } from '../auth';
import { listActiveChannels, listCategories, getChannelByXtreamId } from '../db/channels';
import { createToken, DEFAULT_MANIFEST_TTL } from '../token';
import { buildPlaylist, playlistResponse } from '../playlist/output';
import { jsonResponse, errorResponse, logEvent } from '../utils/http';
import { ErrorCodes } from '../errors/codes';
import { handleHlsManifest } from '../proxy/handlers';
import { isFetchablePort } from '../utils/ports';

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
 * Xtream login.
 *
 * `PUBLIC_PLAYLIST=true` means "anyone may pull the playlist" — /tv.m3u already
 * works without credentials. Xtream clients (TiviMate, Smarters, OTT Navigator)
 * however ALWAYS send a username/password, and previously every one of them was
 * rejected with 401 unless an operator had manually created a D1 user, which is
 * exactly the "can't reach get.php" failure. In public mode we therefore accept
 * any credential as a guest session — including an empty one, since some
 * clients probe the portal before asking the user for credentials. Real D1
 * users still take precedence and a wrong password for an existing user is
 * still rejected.
 */
async function authenticateXtream(env: Env, username: string, password: string): Promise<AuthResult<UserRow>> {
  const direct = await authenticateUser(env, username, password);
  if (direct.ok) return direct;

  const publicMode = (env.PUBLIC_PLAYLIST ?? 'true').toLowerCase() !== 'false';
  if (!publicMode) return direct;
  if (username.length > 128 || password.length > 256) return direct;

  // Only fall back to guest access when this username is not a registered user.
  if (username) {
    const existing = await env.DB.prepare('SELECT 1 AS x FROM users WHERE username = ?').bind(username).first<{ x: number }>();
    if (existing) return direct;
  }

  const ts = Math.floor(Date.now() / 1000);
  const guest: UserRow = {
    id: 0,
    username: username || 'guest',
    password_hash: '',
    password_salt: '',
    status: 'active',
    max_connections: 4,
    expires_at: null,
    created_at: ts,
    updated_at: ts,
  };
  return { ok: true, value: guest };
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

function liveStreamEntry(ch: ChannelRow, i: number) {
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
    direct_source: '',
    tv_archive_duration: 0,
  };
}

export async function handlePlayerApi(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const { username, password, params } = await readCredentials(req);

  const auth = await authenticateXtream(env, username, password);
  if (!auth.ok) {
    logEvent(requestId, '/player_api.php', auth.code);
    // Xtream clients expect a 200 + auth:0 body on bad credentials.
    return jsonResponse({ user_info: { auth: 0, status: 'Disabled' } }, 200);
  }
  const user = auth.value;
  const action = params.get('action') ?? '';
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
      return jsonResponse(filtered.map(liveStreamEntry));
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
  const auth = await authenticateXtream(env, username, password);
  if (!auth.ok) {
    logEvent(requestId, '/panel_api.php', auth.code);
    return jsonResponse({ user_info: { auth: 0, status: 'Disabled' } }, 200);
  }
  const user = auth.value;
  const [channels, cats] = await Promise.all([listActiveChannels(env.DB), listCategories(env.DB)]);
  const categories: Record<string, string> = {};
  for (const c of cats) categories[String(c.id)] = c.name;

  return jsonResponse({
    ...xtreamUserInfo(username, password, user.expires_at, user.max_connections),
    ...serverInfo(url.origin),
    categories: { live: categories, movie: {}, series: {} },
    available_channels: Object.fromEntries(channels.map((ch, i) => [String(ch.xtream_id), liveStreamEntry(ch, i)])),
  });
}

/** /get.php?username=..&password=..&type=m3u_plus — full M3U download. */
export async function handleGetPhp(req: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(req.url);
  const { username, password } = await readCredentials(req);
  const auth = await authenticateXtream(env, username, password);
  if (!auth.ok) {
    logEvent(requestId, '/get.php', auth.code);
    return errorResponse(auth.code, auth.status, requestId);
  }
  const body = await buildPlaylist(env, url.origin);
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
  const auth = await authenticateXtream(env, user, pass);
  if (!auth.ok) {
    logEvent(requestId, '/live', auth.code);
    return errorResponse(auth.code, auth.status, requestId);
  }
  const idPart = streamRef.replace(/\.(m3u8|ts)$/i, '');
  const xtreamId = Number(idPart);
  if (!Number.isInteger(xtreamId)) return errorResponse(ErrorCodes.NOT_FOUND, 404, requestId);
  const channel = await getChannelByXtreamId(env.DB, xtreamId);
  if (!channel) return errorResponse(ErrorCodes.NOT_FOUND, 404, requestId);

  if (!isFetchablePort(channel.url)) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: channel.url,
        'Access-Control-Allow-Origin': '*',
        'X-Request-ID': requestId,
      },
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const token = await createToken(env.SECRET_KEY, {
    u: channel.url,
    iat: now,
    exp: now + DEFAULT_MANIFEST_TTL,
    k: 'm',
    c: channel.id,
  });
  // Serve the proxied manifest directly (no redirect hop for the player).
  return handleHlsManifest(req, env, requestId, token);
}
