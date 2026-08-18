import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { SELF, env, fetchMock } from 'cloudflare:test';
import { createToken, verifyToken } from '../src/token';
import { syncPlaylist } from '../src/playlist/sync';
import { probeChannel, healthCheckBatch, MAX_PROBES_PER_RUN } from '../src/playlist/health';
import { handleHlsManifest, handleSegment } from '../src/proxy/handlers';
import { handleSessionPlaylist } from '../src/auth/loginApi';
import { hashPassword, hmacHex, randomHex } from '../src/utils/crypto';

const ADMIN = { Authorization: `Bearer test-admin-token-0123456789` };
const BASE = 'https://chrtv.example.com';

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});

afterEach(() => {
  fetchMock.assertNoPendingInterceptors();
});

async function seedChannels(): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO categories (name, position) VALUES ('News', 0)"),
    env.DB.prepare(
      `INSERT OR REPLACE INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
       VALUES ('aaaaaaaaaaaaaaa1', 100001, 'VTV1', 'https://up.example.com/live/vtv1/index.m3u8', 'vtv1', '', 1, 0, 1, 1, ?, ?)`,
    ).bind(now, now),
    env.DB.prepare(
      `INSERT OR REPLACE INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
       VALUES ('aaaaaaaaaaaaaaa2', 100002, 'VTV2', 'https://up.example.com/live/vtv2/index.m3u8', 'vtv2', '', 1, 1, 1, 1, ?, ?)`,
    ).bind(now, now),
    env.DB.prepare("UPDATE settings SET value = 'ok' WHERE key = 'sync_status'"),
    env.DB.prepare("UPDATE settings SET value = '2' WHERE key = 'channel_count'"),
  ]);
}

async function seedUser(username: string, password: string): Promise<void> {
  const salt = randomHex(8);
  const hash = await hashPassword(env.SECRET_KEY, salt, password);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT OR REPLACE INTO users (username, password_hash, password_salt, status, max_connections, expires_at, created_at, updated_at)
     VALUES (?, ?, ?, 'active', 1, NULL, ?, ?)`,
  )
    .bind(username, hash, salt, now, now)
    .run();
}

interface LoginResponseBody {
  ok: boolean;
  access_token: string;
  playlist_url: string;
  session: { id: number; device_name: string; created_at: number; expires_at: number | null };
}

async function loginSession(
  username: string,
  password: string,
  deviceName: string,
  ip: string,
  replaceOldest = false,
): Promise<{ response: Response; body: LoginResponseBody | { error: string } }> {
  const response = await SELF.fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': ip,
      'User-Agent': `CHRTV-Test/${deviceName}`,
    },
    body: JSON.stringify({ username, password, device_name: deviceName, replace_oldest: replaceOldest }),
  });
  return { response, body: (await response.json()) as LoginResponseBody | { error: string } };
}

describe('routing basics', () => {
  it('GET / returns the landing page', async () => {
    const res = await SELF.fetch(`${BASE}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('CHRTV');
    expect(html).toContain('Cloud IPTV Gateway');
    expect(html).not.toContain('/tv.m3u');
  });

  it('unknown route returns the Signal Lost 404 page', async () => {
    const res = await SELF.fetch(`${BASE}/does-not-exist`);
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain('Signal Lost');
    expect(html).toContain('404');
    expect(res.headers.get('X-Request-ID')).toBeTruthy();
  });

  it('POST to /tv.m3u returns 405 with Allow header', async () => {
    const res = await SELF.fetch(`${BASE}/tv.m3u`, { method: 'POST' });
    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toContain('GET');
  });

  it('OPTIONS /tv.m3u returns CORS preflight', async () => {
    const res = await SELF.fetch(`${BASE}/tv.m3u`, { method: 'OPTIONS' });
    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
  });

  it('reuses a valid client X-Request-ID', async () => {
    const res = await SELF.fetch(`${BASE}/healthz`, { headers: { 'X-Request-ID': 'client-req-id-123' } });
    expect(res.headers.get('X-Request-ID')).toBe('client-req-id-123');
  });

  it('serves CSP-protected login/admin portals and same-origin scripts without embedding secrets', async () => {
    for (const path of ['/login', '/admin']) {
      const res = await SELF.fetch(`${BASE}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get('Cache-Control')).toBe('no-store');
      expect(res.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
      const html = await res.text();
      expect(html).toContain('CHRTV');
      expect(html).not.toContain(env.ADMIN_TOKEN);
      expect(html).not.toContain(env.SECRET_KEY);
    }
    for (const path of ['/ui/login.js', '/ui/admin.js']) {
      const res = await SELF.fetch(`${BASE}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get('Content-Type')).toContain('javascript');
      expect(await res.text()).toContain('/api/');
    }
  });
});

describe('honeypot bans and private playlist login', () => {
  it('returns a fake 404 for a scanner trap, then enforces a one-day privacy-preserving IP ban', async () => {
    const ip = '203.0.113.201';
    const trap = await SELF.fetch(`${BASE}/.git/config`, { headers: { 'CF-Connecting-IP': ip } });
    expect(trap.status).toBe(404);
    expect(await trap.text()).toContain('Signal Lost');

    const row = await env.DB.prepare("SELECT * FROM security_bans WHERE reason = 'honeypot' ORDER BY last_seen DESC LIMIT 1")
      .first<{ ip_hash: string; expires_at: number; hit_count: number }>();
    expect(row?.ip_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(row?.ip_hash).not.toContain(ip);
    expect(row?.expires_at).toBeGreaterThanOrEqual(Math.floor(Date.now() / 1000) + 86_390);
    expect(row?.hit_count).toBe(1);

    const blocked = await SELF.fetch(`${BASE}/healthz`, { headers: { 'CF-Connecting-IP': ip } });
    expect(blocked.status).toBe(403);
    expect(((await blocked.json()) as { error: string }).error).toBe('SECURITY_BANNED');

    const otherClient = await SELF.fetch(`${BASE}/healthz`, {
      headers: { 'CF-Connecting-IP': '203.0.113.202' },
    });
    expect(otherClient.status).toBe(200);
  });

  it('returns the same fake 404 but does not ban browser-declared cross-site trap requests', async () => {
    const ip = '203.0.113.204';
    const expectedHash = await hmacHex(env.SECRET_KEY, `security-ban|${ip}`);
    const trap = await SELF.fetch(`${BASE}/.env.production`, {
      headers: {
        'CF-Connecting-IP': ip,
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Dest': 'image',
      },
    });
    expect(trap.status).toBe(404);
    expect(await trap.text()).toContain('Signal Lost');
    const ban = await env.DB.prepare('SELECT ip_hash FROM security_bans WHERE ip_hash = ?').bind(expectedHash).first();
    expect(ban).toBeNull();
    const stillAllowed = await SELF.fetch(`${BASE}/healthz`, { headers: { 'CF-Connecting-IP': ip } });
    expect(stillAllowed.status).toBe(200);
  });

  it('lets an admin inspect and remove bans without exposing raw addresses', async () => {
    const ip = '203.0.113.203';
    await SELF.fetch(`${BASE}/wp-login.php`, { headers: { 'CF-Connecting-IP': ip } });

    const list = await SELF.fetch(`${BASE}/api/admin/security-bans`, { headers: ADMIN });
    expect(list.status).toBe(200);
    const bans = (await list.json()) as Array<{ ip_hash: string; reason: string; expires_at: number }>;
    const expectedHash = await hmacHex(env.SECRET_KEY, `security-ban|${ip}`);
    const ban = bans.find((item) => item.ip_hash === expectedHash);
    expect(ban).toMatchObject({ reason: 'honeypot' });
    expect(JSON.stringify(bans)).not.toContain(ip);

    const removed = await SELF.fetch(`${BASE}/api/admin/security-bans/${ban!.ip_hash}`, {
      method: 'DELETE',
      headers: ADMIN,
    });
    expect(removed.status).toBe(200);
    const allowed = await SELF.fetch(`${BASE}/healthz`, { headers: { 'CF-Connecting-IP': ip } });
    expect(allowed.status).toBe(200);
  });

  it('serves /lg/{username}?{password}.m3u only for an authenticated D1 user and binds tokens to that user', async () => {
    await seedChannels();
    await seedUser('private-user', 'private-pass-123');
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'private-user'").first<{ id: number }>();
    const ip = '198.51.100.210';

    const res = await SELF.fetch(`${BASE}/lg/private-user?private-pass-123.m3u`, {
      headers: { 'CF-Connecting-IP': ip },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toContain('no-store');
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    const body = await res.text();
    expect(body).toContain('#EXTM3U');
    expect(body).not.toContain('up.example.com');

    const tokenUrl = body.split('\n').find((line) => line.includes('/hls/'))!;
    const token = tokenUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload).toMatchObject({ uid: user!.id, ip });
    const event = await env.DB.prepare(
      "SELECT user_id, username, event_type, route, outcome, ip_address FROM auth_events WHERE username = 'private-user' ORDER BY id DESC LIMIT 1",
    ).first<{ user_id: number; username: string; event_type: string; route: string; outcome: string; ip_address: string }>();
    expect(event).toMatchObject({
      user_id: user!.id,
      username: 'private-user',
      event_type: 'playlist',
      route: '/lg/:username',
      outcome: 'success',
      ip_address: ip,
    });

    // This endpoint is always private even while PUBLIC_PLAYLIST=true.
    const unknown = await SELF.fetch(`${BASE}/lg/no-such-user?private-pass-123.m3u`, {
      headers: { 'CF-Connecting-IP': '198.51.100.211' },
    });
    expect(unknown.status).toBe(401);
    expect(((await unknown.json()) as { error: string }).error).toBe('AUTH_INVALID');
  });

  it('bans a private-login brute-force source after five failures in ten minutes', async () => {
    await seedUser('brute-target', 'correct-password');
    const ip = '198.51.100.212';
    for (let attempt = 1; attempt <= 4; attempt++) {
      const res = await SELF.fetch(`${BASE}/lg/brute-target?wrong-${attempt}.m3u`, {
        headers: { 'CF-Connecting-IP': ip },
      });
      expect(res.status).toBe(401);
    }
    const failureHash = await hmacHex(env.SECRET_KEY, `security-ban|${ip}`);
    const durableCounter = await env.DB.prepare('SELECT failure_count FROM security_login_failures WHERE ip_hash = ?')
      .bind(failureHash)
      .first<{ failure_count: number }>();
    expect(durableCounter?.failure_count).toBe(4);

    const threshold = await SELF.fetch(`${BASE}/lg/brute-target?wrong-5.m3u`, {
      headers: { 'CF-Connecting-IP': ip },
    });
    expect(threshold.status).toBe(429);
    expect(threshold.headers.get('Retry-After')).toBe('86400');

    const evenCorrectIsBlocked = await SELF.fetch(`${BASE}/lg/brute-target?correct-password.m3u`, {
      headers: { 'CF-Connecting-IP': ip },
    });
    expect(evenCorrectIsBlocked.status).toBe(403);
    const row = await env.DB.prepare("SELECT reason FROM security_bans WHERE reason = 'login-bruteforce' ORDER BY last_seen DESC LIMIT 1")
      .first<{ reason: string }>();
    expect(row?.reason).toBe('login-bruteforce');
    const clearedCounter = await env.DB.prepare('SELECT failure_count FROM security_login_failures WHERE ip_hash = ?')
      .bind(failureHash)
      .first();
    expect(clearedCounter).toBeNull();
  });

  it('rejects malformed private-login URLs without weakening /tv.m3u', async () => {
    const malformed = await SELF.fetch(`${BASE}/lg/user?password=wrong.m3u`);
    expect(malformed.status).toBe(400);
    await seedChannels();
    const publicPlaylist = await SELF.fetch(`${BASE}/tv.m3u`);
    expect(publicPlaylist.status).toBe(200);
    expect(await publicPlaylist.text()).toContain('#EXTM3U');
  });
});

describe('opaque user sessions and authentication audit', () => {
  it('exchanges POSTed credentials for a password-free, revocable M3U session', async () => {
    await seedChannels();
    await seedUser('safe-session-user', 'safe-password-123');
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'safe-session-user'").first<{ id: number }>();
    const ip = '198.51.100.220';
    const login = await loginSession('safe-session-user', 'safe-password-123', 'Living Room TV', ip);
    expect(login.response.status).toBe(201);
    expect(login.response.headers.get('Cache-Control')).toContain('no-store');
    const body = login.body as LoginResponseBody;
    expect(body.access_token).toMatch(/^[a-f0-9]{64}$/);
    expect(body.playlist_url).toBe(`${BASE}/p/${body.access_token}.m3u`);
    expect(body.playlist_url).not.toContain('safe-session-user');
    expect(body.playlist_url).not.toContain('safe-password-123');

    const stored = await env.DB.prepare(
      'SELECT token_hash, token_prefix, device_name, ip_address, last_ip, status FROM user_sessions WHERE id = ?',
    )
      .bind(body.session.id)
      .first<{ token_hash: string; token_prefix: string; device_name: string; ip_address: string; last_ip: string; status: string }>();
    expect(stored).toMatchObject({
      token_prefix: body.access_token.slice(0, 12),
      device_name: 'Living Room TV',
      ip_address: ip,
      last_ip: ip,
      status: 'active',
    });
    expect(stored!.token_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored!.token_hash).not.toBe(body.access_token);

    const playlist = await SELF.fetch(body.playlist_url, {
      headers: { 'CF-Connecting-IP': ip, 'User-Agent': 'CHRTV-Test/Playback' },
    });
    expect(playlist.status).toBe(200);
    const m3u = await playlist.text();
    expect(m3u).toContain('#EXTM3U');
    expect(m3u).not.toContain('safe-password-123');
    expect(m3u).not.toContain('up.example.com');
    const mediaUrl = m3u.split('\n').find((line) => line.includes('/hls/'))!;
    const mediaToken = mediaUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const media = await verifyToken(env.SECRET_KEY, mediaToken);
    expect(media.ok).toBe(true);
    if (media.ok) expect(media.payload).toMatchObject({ uid: user!.id, sid: body.session.id, ip, k: 'm' });

    const account = await SELF.fetch(`${BASE}/api/account/sessions`, {
      headers: { Authorization: `Bearer ${body.access_token}`, 'CF-Connecting-IP': '198.51.100.221' },
    });
    expect(account.status).toBe(200);
    const accountBody = (await account.json()) as {
      current_session_id: number;
      user: { username: string; max_connections: number };
      sessions: Array<{ id: number; last_ip: string }>;
    };
    expect(accountBody.user).toMatchObject({ username: 'safe-session-user', max_connections: 1 });
    expect(accountBody.current_session_id).toBe(body.session.id);
    expect(accountBody.sessions.find((session) => session.id === body.session.id)?.last_ip).toBe('198.51.100.221');

    const events = await env.DB.prepare(
      "SELECT event_type, outcome, ip_address, user_id, session_id FROM auth_events WHERE username = 'safe-session-user' ORDER BY id",
    ).all<{ event_type: string; outcome: string; ip_address: string; user_id: number; session_id: number }>();
    expect(events.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ event_type: 'login', outcome: 'success', ip_address: ip, user_id: user!.id }),
        expect.objectContaining({ event_type: 'playlist', outcome: 'success', ip_address: ip, session_id: body.session.id }),
      ]),
    );

    const revoked = await SELF.fetch(`${BASE}/api/account/sessions/${body.session.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${body.access_token}` },
    });
    expect(revoked.status).toBe(200);
    const blocked = await SELF.fetch(body.playlist_url);
    expect(blocked.status).toBe(403);
    expect(((await blocked.json()) as { error: string }).error).toBe('AUTH_DISABLED');

    // A previously downloaded channel capability is also stopped before the
    // next manifest fetch. Descendant segments already issued by an earlier
    // manifest remain short-lived and cannot outlive this parent capability.
    const revokedMedia = await SELF.fetch(mediaUrl, {
      headers: { 'CF-Connecting-IP': ip },
      redirect: 'manual',
    });
    expect(revokedMedia.status).toBe(403);
    expect(((await revokedMedia.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });

  it('rejects an issued session capability after session expiry, user disablement, or user expiry', async () => {
    await seedChannels();
    await seedUser('active-session-checks', 'active-password-123');
    const login = await loginSession('active-session-checks', 'active-password-123', 'Expiry TV', '198.51.100.225');
    expect(login.response.status).toBe(201);
    const body = login.body as LoginResponseBody;
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'active-session-checks'").first<{ id: number }>();
    const now = Math.floor(Date.now() / 1000);
    const earlierSessionExpiry = now + 3600;
    await env.DB.prepare('UPDATE user_sessions SET expires_at = ? WHERE id = ?').bind(earlierSessionExpiry, body.session.id).run();
    await env.DB.prepare('UPDATE users SET expires_at = ? WHERE id = ?').bind(now + 7200, user!.id).run();
    const playlist = await SELF.fetch(body.playlist_url, { headers: { 'CF-Connecting-IP': '198.51.100.225' } });
    const mediaUrl = (await playlist.text()).split('\n').find((line) => line.includes('/hls/'))!;
    const mediaToken = mediaUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const issued = await verifyToken(env.SECRET_KEY, mediaToken);
    expect(issued.ok).toBe(true);
    if (issued.ok) expect(issued.payload.exp).toBe(earlierSessionExpiry);

    await env.DB.prepare('UPDATE user_sessions SET expires_at = ? WHERE id = ?').bind(now - 1, body.session.id).run();
    expect((await SELF.fetch(mediaUrl, { headers: { 'CF-Connecting-IP': '198.51.100.225' } })).status).toBe(403);

    await env.DB.prepare('UPDATE user_sessions SET expires_at = NULL WHERE id = ?').bind(body.session.id).run();
    await env.DB.prepare("UPDATE users SET status = 'disabled', expires_at = NULL WHERE id = ?").bind(user!.id).run();
    expect((await SELF.fetch(mediaUrl, { headers: { 'CF-Connecting-IP': '198.51.100.225' } })).status).toBe(403);

    await env.DB.prepare("UPDATE users SET status = 'active', expires_at = ? WHERE id = ?").bind(now - 1, user!.id).run();
    const expiredUser = await SELF.fetch(mediaUrl, { headers: { 'CF-Connecting-IP': '198.51.100.225' } });
    expect(expiredUser.status).toBe(403);
    expect(((await expiredUser.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });

  it('keeps session ownership authorization active when TOKEN_BINDING=none', async () => {
    await seedChannels();
    await seedUser('none-binding-session', 'none-password-123');
    const login = await loginSession('none-binding-session', 'none-password-123', 'Unbound TV', '198.51.100.226');
    expect(login.response.status).toBe(201);
    const body = login.body as LoginResponseBody;
    const noBindingEnv = { ...env, TOKEN_BINDING: 'none' };
    const playlist = await handleSessionPlaylist(
      new Request(body.playlist_url, { headers: { 'CF-Connecting-IP': '198.51.100.226' } }),
      noBindingEnv,
      'req-none-binding-playlist',
      `${body.access_token}.m3u`,
    );
    expect(playlist.status).toBe(200);
    const mediaUrl = (await playlist.text()).split('\n').find((line) => line.includes('/hls/'))!;
    const token = mediaUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.payload).toMatchObject({ sid: body.session.id, k: 'm' });
      expect(verdict.payload.uid).toBeGreaterThan(0);
      expect(verdict.payload.ip).toBeUndefined();
    }

    fetchMock
      .get('https://up.example.com')
      .intercept({ path: '/live/vtv1/index.m3u8' })
      .reply(200, '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nseg.ts\n#EXT-X-ENDLIST\n');
    const active = await handleHlsManifest(new Request(mediaUrl), noBindingEnv, 'req-none-binding-active', token);
    expect(active.status).toBe(200);

    await env.DB.prepare("UPDATE user_sessions SET status = 'revoked' WHERE id = ?").bind(body.session.id).run();
    const revoked = await handleHlsManifest(new Request(mediaUrl), noBindingEnv, 'req-none-binding-revoked', token);
    expect(revoked.status).toBe(403);
    expect(((await revoked.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });

  it('enforces max_connections, optionally replaces the oldest session, and scopes revocation by user', async () => {
    await seedUser('limit-session-user', 'limit-password-123');
    await seedUser('other-session-user', 'other-password-123');
    const first = await loginSession('limit-session-user', 'limit-password-123', 'Old TV', '198.51.100.222');
    expect(first.response.status).toBe(201);
    const firstBody = first.body as LoginResponseBody;

    const limited = await loginSession('limit-session-user', 'limit-password-123', 'New TV', '198.51.100.223');
    expect(limited.response.status).toBe(409);
    expect(limited.body).toMatchObject({ error: 'SESSION_LIMIT' });

    const replacement = await loginSession('limit-session-user', 'limit-password-123', 'New TV', '198.51.100.223', true);
    expect(replacement.response.status).toBe(201);
    const replacementBody = replacement.body as LoginResponseBody;
    expect(replacementBody.session.id).not.toBe(firstBody.session.id);
    expect((await SELF.fetch(firstBody.playlist_url)).status).toBe(403);

    const other = await loginSession('other-session-user', 'other-password-123', 'Other TV', '198.51.100.224');
    expect(other.response.status).toBe(201);
    const otherBody = other.body as LoginResponseBody;
    const crossAccount = await SELF.fetch(`${BASE}/api/account/sessions/${otherBody.session.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${replacementBody.access_token}` },
    });
    expect(crossAccount.status).toBe(404);
    const otherStillActive = await SELF.fetch(`${BASE}/api/account/sessions`, {
      headers: { Authorization: `Bearer ${otherBody.access_token}` },
    });
    expect(otherStillActive.status).toBe(200);

    const limitEvent = await env.DB.prepare(
      "SELECT outcome, ip_address FROM auth_events WHERE username = 'limit-session-user' AND outcome = 'limit' ORDER BY id DESC LIMIT 1",
    ).first<{ outcome: string; ip_address: string }>();
    expect(limitEvent).toEqual({ outcome: 'limit', ip_address: '198.51.100.223' });
  });

  it('lets admins inspect/revoke sessions and keeps account/session expiry in sync', async () => {
    await seedUser('admin-session-user', 'admin-password-123');
    const login = await loginSession('admin-session-user', 'admin-password-123', 'Admin Managed TV', '192.0.2.230');
    expect(login.response.status).toBe(201);
    const body = login.body as LoginResponseBody;
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin-session-user'").first<{ id: number }>();
    const expiry = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;

    const patch = await SELF.fetch(`${BASE}/api/admin/users/${user!.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_connections: 3, expires_at: expiry }),
    });
    expect(patch.status).toBe(200);
    const synchronized = await env.DB.prepare(
      'SELECT u.max_connections, u.expires_at AS user_expiry, s.expires_at AS session_expiry FROM users u JOIN user_sessions s ON s.user_id = u.id WHERE s.id = ?',
    )
      .bind(body.session.id)
      .first<{ max_connections: number; user_expiry: number; session_expiry: number }>();
    expect(synchronized).toEqual({ max_connections: 3, user_expiry: expiry, session_expiry: expiry });

    const sessions = (await (await SELF.fetch(`${BASE}/api/admin/sessions`, { headers: ADMIN })).json()) as Array<{
      id: number;
      username: string;
      ip_address: string;
    }>;
    expect(sessions).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: body.session.id, username: 'admin-session-user', ip_address: '192.0.2.230' })]),
    );
    const events = (await (
      await SELF.fetch(`${BASE}/api/admin/auth-events?limit=1000`, { headers: ADMIN })
    ).json()) as Array<{ username: string; ip_address: string; outcome: string }>;
    expect(events).toEqual(
      expect.arrayContaining([expect.objectContaining({ username: 'admin-session-user', ip_address: '192.0.2.230', outcome: 'success' })]),
    );

    const revoke = await SELF.fetch(`${BASE}/api/admin/sessions/${body.session.id}`, { method: 'DELETE', headers: ADMIN });
    expect(revoke.status).toBe(200);
    expect((await SELF.fetch(body.playlist_url)).status).toBe(403);

    const second = await loginSession('admin-session-user', 'admin-password-123', 'Second TV', '192.0.2.231');
    expect(second.response.status).toBe(201);
    const disable = await SELF.fetch(`${BASE}/api/admin/users/${user!.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'disabled' }),
    });
    expect(disable.status).toBe(200);
    const sessionStatus = await env.DB.prepare('SELECT status FROM user_sessions WHERE id = ?')
      .bind((second.body as LoginResponseBody).session.id)
      .first<{ status: string }>();
    expect(sessionStatus?.status).toBe('revoked');
    expect((await SELF.fetch((second.body as LoginResponseBody).playlist_url)).status).toBe(403);

    const badLimit = await SELF.fetch(`${BASE}/api/admin/users/${user!.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_connections: 101 }),
    });
    expect(badLimit.status).toBe(400);
  });
});

describe('/tv.m3u playlist', () => {
  it('serves and audits a tokenized public playlist with zero credentials', async () => {
    await seedChannels();
    const ip = '192.0.2.244';
    const res = await SELF.fetch(`${BASE}/tv.m3u`, { headers: { 'CF-Connecting-IP': ip } });
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('mpegurl');
    const body = await res.text();
    expect(body.startsWith('#EXTM3U')).toBe(true);
    expect(body).toContain('VTV1');
    expect(body).toContain(`${BASE}/hls/`);
    expect(body).not.toContain('up.example.com'); // upstream never exposed
    const event = await env.DB.prepare(
      "SELECT username, event_type, route, outcome, ip_address FROM auth_events WHERE route = '/tv.m3u' ORDER BY id DESC LIMIT 1",
    ).first<{ username: string; event_type: string; route: string; outcome: string; ip_address: string }>();
    expect(event).toEqual({ username: '', event_type: 'playlist', route: '/tv.m3u', outcome: 'success', ip_address: ip });
  });

  it('keeps custom-port channels opaque and never reveals their origin in a redirect', async () => {
    await seedChannels();
    const now = Math.floor(Date.now() / 1000);
    const upstream = 'http://chrtv.duckdns.org:4000/hls/hbo/master.m3u8';
    await env.DB.prepare(
      `INSERT OR REPLACE INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
       VALUES ('aaaaaaaaaaaaaaa3', 100003, 'HBO Custom', ?, 'hbo-custom', '', 1, 2, 1, 1, ?, ?)`,
    ).bind(upstream, now, now).run();

    const res = await SELF.fetch(`${BASE}/tv.m3u`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('HBO Custom');
    expect(body).not.toContain(upstream); // no raw upstream leaks in the M3U

    const lines = body.trim().split('\n');
    const hboInfo = lines.findIndex((line) => line.includes('HBO Custom'));
    const tokenUrl = lines[hboInfo + 1]!;
    expect(tokenUrl).toContain(`${BASE}/hls/`);
    const token = tokenUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload.u).toBe(upstream);

    // Workers cannot fetch this port. Even after token authentication, CHRTV
    // fails closed to a valid error manifest and never returns the raw origin.
    const stream = await SELF.fetch(tokenUrl, { redirect: 'manual' });
    expect(stream.status).toBe(200);
    expect(stream.headers.get('Location')).toBeNull();
    expect(stream.headers.get('X-CHRTV-Fallback')).toBe('1');
    const streamBody = await stream.text();
    expect(streamBody).toContain('#EXTM3U');
    expect(streamBody).not.toContain('#EXT-X-ENDLIST'); // live fallback: player keeps retrying
    expect(streamBody).not.toContain(upstream);
    expect(streamBody).not.toContain('chrtv.duckdns.org');
  });

  it('/xem.m3u is an alias of the same playlist', async () => {
    await seedChannels();
    const [a, b] = await Promise.all([SELF.fetch(`${BASE}/tv.m3u`), SELF.fetch(`${BASE}/xem.m3u`)]);
    const [ta, tb] = await Promise.all([a.text(), b.text()]);
    expect(tb.split('\n')[0]).toBe(ta.split('\n')[0]);
    expect(tb).toContain('VTV1');
  });

  it('HEAD /tv.m3u returns headers without a body', async () => {
    await seedChannels();
    const res = await SELF.fetch(`${BASE}/tv.m3u`, { method: 'HEAD' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
  });

  it('rejects an invalid access key even in public mode and records the raw source IP', async () => {
    const ip = '192.0.2.240';
    const res = await SELF.fetch(`${BASE}/tv.m3u?key=chr_definitely_wrong_key`, {
      headers: { 'CF-Connecting-IP': ip },
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('KEY_INVALID');
    const event = await env.DB.prepare(
      "SELECT event_type, route, outcome, ip_address FROM auth_events WHERE event_type = 'access_key' AND ip_address = ? ORDER BY id DESC LIMIT 1",
    )
      .bind(ip)
      .first<{ event_type: string; route: string; outcome: string; ip_address: string }>();
    expect(event).toEqual({ event_type: 'access_key', route: '/tv.m3u', outcome: 'failure', ip_address: ip });
  });
});

describe('access keys + MAC devices', () => {
  async function createKey(maxDevices = 2, userId?: number): Promise<string> {
    const res = await SELF.fetch(`${BASE}/api/admin/keys`, {
      method: 'POST',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: 'test', max_devices: maxDevices, ...(userId ? { user_id: userId } : {}) }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { access_key: string };
    expect(body.access_key.startsWith('chr_')).toBe(true);
    return body.access_key;
  }

  it('registers devices by normalized MAC and enforces the device limit', async () => {
    await seedChannels();
    const key = await createKey(2);

    // Same MAC in two formats => one device
    const r1 = await SELF.fetch(`${BASE}/tv.m3u?key=${key}&mac=aa:bb:cc:00:11:22`);
    expect(r1.status).toBe(200);
    const r2 = await SELF.fetch(`${BASE}/tv.m3u?key=${key}&mac=AA-BB-CC-00-11-22`);
    expect(r2.status).toBe(200);
    const devices = await env.DB.prepare('SELECT mac_address FROM devices').all();
    expect(devices.results).toHaveLength(1);
    expect((devices.results[0] as { mac_address: string }).mac_address).toBe('AA:BB:CC:00:11:22');

    // Second and third distinct MACs
    const r3 = await SELF.fetch(`${BASE}/tv.m3u?key=${key}&mac=aa:bb:cc:00:11:33`);
    expect(r3.status).toBe(200);
    const r4 = await SELF.fetch(`${BASE}/tv.m3u?key=${key}&mac=aa:bb:cc:00:11:44`);
    expect(r4.status).toBe(403);
    expect(((await r4.json()) as { error: string }).error).toBe('DEVICE_LIMIT');
  });

  it('personalizes tokens by Cloudflare IP, normalized MAC, access-key id, and linked user id', async () => {
    await seedChannels();
    await seedUser('bound-user', 'password123');
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'bound-user'").first<{ id: number }>();
    const key = await createKey(2, user!.id);

    const playlist = await SELF.fetch(`${BASE}/tv.m3u?key=${key}&mac=aa-bb-cc-11-22-33`, {
      headers: { 'CF-Connecting-IP': '203.0.113.10' },
    });
    expect(playlist.status).toBe(200);
    const body = await playlist.text();
    const tokenUrl = body.split('\n').find((line) => line.includes('/hls/'))!;
    const token = tokenUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;

    const keyRow = await env.DB.prepare('SELECT id, user_id FROM access_keys WHERE id = ?')
      .bind(verdict.payload.aid)
      .first<{ id: number; user_id: number }>();
    expect(verdict.payload).toMatchObject({
      ip: '203.0.113.10',
      mac: 'AA:BB:CC:11:22:33',
      uid: user!.id,
      aid: keyRow!.id,
    });
    expect(keyRow!.user_id).toBe(user!.id);

    // The IP is independently observed by Cloudflare and strictly enforced.
    // No upstream mock is registered, so a successful rejection cannot have
    // reached the channel origin.
    const stolen = await SELF.fetch(tokenUrl, {
      headers: { 'CF-Connecting-IP': '203.0.113.99' },
      redirect: 'manual',
    });
    expect(stolen.status).toBe(403);
    expect(((await stolen.json()) as { error: string }).error).toBe('TOKEN_BINDING_MISMATCH');
  });

  it('rejects a linked key when its owner user is disabled', async () => {
    await seedUser('disabled-owner', 'password123');
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'disabled-owner'").first<{ id: number }>();
    const key = await createKey(2, user!.id);
    await env.DB.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").bind(user!.id).run();

    const res = await SELF.fetch(`${BASE}/tv.m3u?key=${key}`);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });

  it('rejects an issued key capability after key expiry, ownership changes, or owner expiry', async () => {
    await seedChannels();
    await seedUser('issued-key-owner-a', 'password123');
    await seedUser('issued-key-owner-b', 'password123');
    const ownerA = await env.DB.prepare("SELECT id FROM users WHERE username = 'issued-key-owner-a'").first<{ id: number }>();
    const ownerB = await env.DB.prepare("SELECT id FROM users WHERE username = 'issued-key-owner-b'").first<{ id: number }>();
    const key = await createKey(2, ownerA!.id);
    const issued = await SELF.fetch(`${BASE}/tv.m3u?key=${key}`);
    expect(issued.status).toBe(200);
    const mediaUrl = (await issued.text()).split('\n').find((line) => line.includes('/hls/'))!;
    const token = mediaUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    const keyId = verdict.ok ? verdict.payload.aid! : 0;
    const now = Math.floor(Date.now() / 1000);

    await env.DB.prepare('UPDATE access_keys SET expires_at = ? WHERE id = ?').bind(now - 1, keyId).run();
    expect((await SELF.fetch(mediaUrl)).status).toBe(403);

    await env.DB.prepare('UPDATE access_keys SET expires_at = NULL, user_id = ? WHERE id = ?').bind(ownerB!.id, keyId).run();
    expect((await SELF.fetch(mediaUrl)).status).toBe(403);

    await env.DB.prepare('UPDATE access_keys SET user_id = ? WHERE id = ?').bind(ownerA!.id, keyId).run();
    await env.DB.prepare('UPDATE users SET expires_at = ? WHERE id = ?').bind(now - 1, ownerA!.id).run();
    const expiredOwner = await SELF.fetch(mediaUrl);
    expect(expiredOwner.status).toBe(403);
    expect(((await expiredOwner.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });

  it('revoked keys and their previously downloaded manifest capabilities are rejected', async () => {
    await seedChannels();
    const key = await createKey();
    const issued = await SELF.fetch(`${BASE}/tv.m3u?key=${key}`);
    expect(issued.status).toBe(200);
    const tokenUrl = (await issued.text()).split('\n').find((line) => line.includes('/hls/'))!;

    const list = await SELF.fetch(`${BASE}/api/admin/keys`, { headers: ADMIN });
    const keys = (await list.json()) as Array<{ id: number; key_prefix: string }>;
    const row = keys.find((k) => key.startsWith(k.key_prefix))!;
    const del = await SELF.fetch(`${BASE}/api/admin/keys/${row.id}`, { method: 'DELETE', headers: ADMIN });
    expect(del.status).toBe(200);
    const res = await SELF.fetch(`${BASE}/tv.m3u?key=${key}`);
    expect(res.status).toBe(403);

    const media = await SELF.fetch(tokenUrl, { redirect: 'manual' });
    expect(media.status).toBe(403);
    expect(((await media.json()) as { error: string }).error).toBe('AUTH_DISABLED');
  });
});

describe('admin API', () => {
  it('requires a bearer token', async () => {
    const res = await SELF.fetch(`${BASE}/api/admin/status`);
    expect(res.status).toBe(401);
    const bad = await SELF.fetch(`${BASE}/api/admin/status`, { headers: { Authorization: 'Bearer wrong-token-000000' } });
    expect(bad.status).toBe(401);
  });

  it('returns status without secrets', async () => {
    const res = await SELF.fetch(`${BASE}/api/admin/status`, { headers: ADMIN });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain('test-secret-key');
    expect(text).not.toContain('password_hash');
    const body = JSON.parse(text) as { service: string; stats: unknown };
    expect(body.service).toBe('CHRTV');
  });

  it('user CRUD works and never leaks hashes', async () => {
    const create = await SELF.fetch(`${BASE}/api/admin/users`, {
      method: 'POST',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'supersecret1' }),
    });
    expect(create.status).toBe(201);

    const list = await SELF.fetch(`${BASE}/api/admin/users`, { headers: ADMIN });
    const users = (await list.json()) as Array<{ id: number; username: string; password_hash?: string }>;
    const alice = users.find((u) => u.username === 'alice')!;
    expect(alice).toBeTruthy();
    expect(alice.password_hash).toBeUndefined();

    const disable = await SELF.fetch(`${BASE}/api/admin/users/${alice.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'disabled' }),
    });
    expect(disable.status).toBe(200);
    const row = await env.DB.prepare('SELECT status FROM users WHERE id = ?').bind(alice.id).first<{ status: string }>();
    expect(row?.status).toBe('disabled');

    // re-enable
    await SELF.fetch(`${BASE}/api/admin/users/${alice.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'active' }),
    });
  });

  it('links and clears an access-key owner by user id', async () => {
    await seedUser('key-owner', 'password123');
    const owner = await env.DB.prepare("SELECT id FROM users WHERE username = 'key-owner'").first<{ id: number }>();
    const create = await SELF.fetch(`${BASE}/api/admin/keys`, {
      method: 'POST',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: 'owner test' }),
    });
    const created = (await create.json()) as { access_key: string };
    const list = await SELF.fetch(`${BASE}/api/admin/keys`, { headers: ADMIN });
    const key = ((await list.json()) as Array<{ id: number; key_prefix: string }>).find((row) =>
      created.access_key.startsWith(row.key_prefix),
    )!;

    const link = await SELF.fetch(`${BASE}/api/admin/keys/${key.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: owner!.id }),
    });
    expect(link.status).toBe(200);
    const linked = await env.DB.prepare('SELECT user_id, username FROM access_keys WHERE id = ?')
      .bind(key.id)
      .first<{ user_id: number | null; username: string }>();
    expect(linked).toEqual({ user_id: owner!.id, username: 'key-owner' });

    const clear = await SELF.fetch(`${BASE}/api/admin/keys/${key.id}`, {
      method: 'PATCH',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: null }),
    });
    expect(clear.status).toBe(200);
    const cleared = await env.DB.prepare('SELECT user_id, username FROM access_keys WHERE id = ?')
      .bind(key.id)
      .first<{ user_id: number | null; username: string }>();
    expect(cleared).toEqual({ user_id: null, username: '' });
  });

  it('rejects weak user input', async () => {
    const res = await SELF.fetch(`${BASE}/api/admin/users`, {
      method: 'POST',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'x', password: 'short' }),
    });
    expect(res.status).toBe(400);
  });
});

describe('Xtream Codes API', () => {
  it('handshake authenticates and bad credentials return auth:0', async () => {
    await seedUser('bob', 'password123');
    const ok = await SELF.fetch(`${BASE}/player_api.php?username=bob&password=password123`);
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { user_info: { auth: number }; server_info: { url: string } };
    expect(body.user_info.auth).toBe(1);
    expect(body.server_info.url).toBe('chrtv.example.com');

    const bad = await SELF.fetch(`${BASE}/player_api.php?username=bob&password=nope`);
    expect(bad.status).toBe(200);
    expect(((await bad.json()) as { user_info: { auth: number } }).user_info.auth).toBe(0);
  });

  it('get_live_categories and get_live_streams', async () => {
    await seedChannels();
    await seedUser('bob', 'password123');
    const cats = await SELF.fetch(`${BASE}/player_api.php?username=bob&password=password123&action=get_live_categories`);
    const catList = (await cats.json()) as Array<{ category_name: string }>;
    expect(catList.some((c) => c.category_name === 'News')).toBe(true);

    const streams = await SELF.fetch(`${BASE}/player_api.php?username=bob&password=password123&action=get_live_streams`);
    const list = (await streams.json()) as Array<{ name: string; stream_id: number; direct_source: string }>;
    expect(list.length).toBeGreaterThanOrEqual(2);
    expect(list[0]!.direct_source).toMatch(/^https:\/\/chrtv\.example\.com\/hls\/.+\.m3u8$/);
    expect(list[0]!.direct_source).not.toContain('up.example.com');
    const directToken = list[0]!.direct_source.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, directToken);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload).toMatchObject({ k: 'm' });
    expect(list.some((s) => s.name === 'VTV1')).toBe(true);
  });

  it('get.php requires valid credentials, returns tokenized M3U, and audits raw IP/outcome', async () => {
    await seedChannels();
    await seedUser('bob', 'password123');
    const bob = await env.DB.prepare("SELECT id FROM users WHERE username = 'bob'").first<{ id: number }>();
    const badIp = '192.0.2.242';
    const goodIp = '192.0.2.243';
    const bad = await SELF.fetch(`${BASE}/get.php?username=bob&password=wrong`, {
      headers: { 'CF-Connecting-IP': badIp },
    });
    expect(bad.status).toBe(401);
    const ok = await SELF.fetch(`${BASE}/get.php?username=bob&password=password123&type=m3u_plus`, {
      headers: { 'CF-Connecting-IP': goodIp },
    });
    expect(ok.status).toBe(200);
    const text = await ok.text();
    expect(text).toContain('#EXTM3U');
    expect(text).not.toContain('up.example.com');
    const events = await env.DB.prepare(
      "SELECT event_type, route, outcome, ip_address, user_id FROM auth_events WHERE username = 'bob' AND route = '/get.php' ORDER BY id DESC LIMIT 2",
    ).all<{ event_type: string; route: string; outcome: string; ip_address: string; user_id: number | null }>();
    expect(events.results).toEqual(
      expect.arrayContaining([
        { event_type: 'playlist', route: '/get.php', outcome: 'failure', ip_address: badIp, user_id: null },
        { event_type: 'playlist', route: '/get.php', outcome: 'success', ip_address: goodIp, user_id: bob!.id },
      ]),
    );
  });

  it('get.php binds its M3U tokens to the authenticated D1 user id and client IP', async () => {
    await seedChannels();
    await seedUser('token-user', 'password123');
    const user = await env.DB.prepare("SELECT id FROM users WHERE username = 'token-user'").first<{ id: number }>();
    const res = await SELF.fetch(`${BASE}/get.php?username=token-user&password=password123&mac=0011.2233.4455`, {
      headers: { 'CF-Connecting-IP': '192.0.2.44' },
    });
    expect(res.status).toBe(200);
    const tokenUrl = (await res.text()).split('\n').find((line) => line.includes('/hls/'))!;
    const token = tokenUrl.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.payload).toMatchObject({ ip: '192.0.2.44', mac: '00:11:22:33:44:55', uid: user!.id });
      expect(verdict.payload.aid).toBeUndefined();
    }
  });

  it('does not turn PUBLIC_PLAYLIST into anonymous Xtream access', async () => {
    await seedChannels();
    const get = await SELF.fetch(`${BASE}/get.php?username=anyuser&password=anypass&type=m3u_plus&output=m3u8`);
    expect(get.status).toBe(401);
    const player = await SELF.fetch(`${BASE}/player_api.php?username=guest1&password=guest1`);
    expect(player.status).toBe(200);
    expect(((await player.json()) as { user_info: { auth: number } }).user_info.auth).toBe(0);
  });

  it('a wrong password for an EXISTING user is still rejected', async () => {
    await seedUser('bob', 'password123');
    const res = await SELF.fetch(`${BASE}/get.php?username=bob&password=totally-wrong`);
    expect(res.status).toBe(401);
  });

  it('/player-api.php alias works', async () => {
    await seedUser('bob', 'password123');
    const res = await SELF.fetch(`${BASE}/player-api.php?username=bob&password=password123`);
    expect(res.status).toBe(200);
  });

  it('accepts POSTed JSON credentials (IPTV Smarters style)', async () => {
    await seedChannels();
    await seedUser('jsonuser', 'jsonpass123');
    const res = await SELF.fetch(`${BASE}/player_api.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'jsonuser', password: 'jsonpass123' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user_info: { auth: number }; server_info: { url: string } };
    expect(body.user_info.auth).toBe(1);
    expect(body.server_info.url).toBe('chrtv.example.com');
  });

  it('accepts HTTP Basic credentials', async () => {
    await seedUser('basicuser', 'basicpass123');
    const res = await SELF.fetch(`${BASE}/player_api.php`, {
      headers: { Authorization: `Basic ${btoa('basicuser:basicpass123')}` },
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { user_info: { auth: number } }).user_info.auth).toBe(1);
  });

  it('rejects a credential-free handshake even when /tv.m3u is public', async () => {
    const res = await SELF.fetch(`${BASE}/player_api.php`);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { user_info: { auth: number } }).user_info.auth).toBe(0);
  });

  it('advertises both m3u8 and ts output formats', async () => {
    await seedUser('fmtuser', 'fmtpass123');
    const res = await SELF.fetch(`${BASE}/player_api.php?username=fmtuser&password=fmtpass123`);
    const body = (await res.json()) as { user_info: { allowed_output_formats: string[] } };
    expect(body.user_info.allowed_output_formats).toContain('m3u8');
    expect(body.user_info.allowed_output_formats).toContain('ts');
  });

  it('an unknown action still returns a valid authenticated payload', async () => {
    await seedUser('unknownaction', 'unknownpass123');
    const res = await SELF.fetch(`${BASE}/player_api.php?username=unknownaction&password=unknownpass123&action=get_something_new`);
    const body = (await res.json()) as { user_info: { auth: number } };
    expect(body.user_info.auth).toBe(1);
  });

  it('/panel_api.php returns user_info plus the channel map', async () => {
    await seedChannels();
    await seedUser('paneluser', 'panelpass123');
    const res = await SELF.fetch(`${BASE}/panel_api.php?username=paneluser&password=panelpass123`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      user_info: { auth: number };
      available_channels: Record<string, { name: string }>;
      categories: { live: Record<string, string> };
    };
    expect(body.user_info.auth).toBe(1);
    expect(body.available_channels['100001']!.name).toBe('VTV1');
    expect(Object.values(body.categories.live)).toContain('News');
  });

  it('accepts POSTed form credentials', async () => {
    await seedUser('bob', 'password123');
    const res = await SELF.fetch(`${BASE}/player_api.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=bob&password=password123',
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { user_info: { auth: number } }).user_info.auth).toBe(1);
  });
});

describe('HLS proxy', () => {
  async function mintToken(upstream: string, opts: { exp?: number; channel?: string } = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return createToken(env.SECRET_KEY, {
      u: upstream,
      iat: now,
      exp: opts.exp ?? now + 300,
      k: 'm',
      ...(opts.channel ? { c: opts.channel } : {}),
    });
  }

  it('rejects garbage tokens with 403 (real HTTP error, not fallback)', async () => {
    const res = await SELF.fetch(`${BASE}/hls/not-a-real-token.m3u8`);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('TOKEN_INVALID');
  });

  it('rejects expired tokens with 410', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await mintToken('https://up1.example.com/x.m3u8', { exp: now - 10 });
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(410);
    expect(((await res.json()) as { error: string }).error).toBe('TOKEN_EXPIRED');
  });

  it('treats token kinds as route capabilities and rejects cross-route substitution', async () => {
    const now = Math.floor(Date.now() / 1000);
    const segment = await createToken(env.SECRET_KEY, {
      u: 'https://kind.example.com/segment.ts',
      iat: now,
      exp: now + 300,
      k: 's',
    });
    const epg = await createToken(env.SECRET_KEY, {
      u: 'https://epg-token.chrtv.invalid/xmltv.xml',
      iat: now,
      exp: now + 300,
      k: 'e',
    });
    const manifest = await mintToken('https://kind.example.com/index.m3u8');
    for (const url of [`${BASE}/hls/${segment}.m3u8`, `${BASE}/hls/${epg}.m3u8`, `${BASE}/seg/${manifest}.m3u8`]) {
      const res = await SELF.fetch(url);
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe('TOKEN_INVALID');
    }
  });

  it('proxies and rewrites a valid manifest (relative URIs, EXT-X-KEY)', async () => {
    const manifest = [
      '#EXTM3U',
      '#EXT-X-VERSION:3',
      '#EXT-X-TARGETDURATION:6',
      '#EXT-X-KEY:METHOD=AES-128,URI="enc.key"',
      '#EXTINF:6.0,',
      'seg001.ts',
      '#EXT-X-ENDLIST',
    ].join('\n');
    fetchMock
      .get('https://up2.example.com')
      .intercept({ path: '/live/ch/index.m3u8' })
      .reply(200, manifest, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });

    const token = await mintToken('https://up2.example.com/live/ch/index.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('mpegurl');
    const body = await res.text();
    expect(body).toContain(`${BASE}/seg/`);
    expect(body).not.toContain('up2.example.com');
    expect(body).toContain('METHOD=AES-128');
    expect(res.headers.get('X-CHRTV-Fallback')).toBeNull();
  });

  it('fails closed when an upstream manifest contains an unsafe descendant URI', async () => {
    const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nhttp://169.254.169.254/latest/meta-data\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://unsafe-child.example.com').intercept({ path: '/index.m3u8' }).reply(200, manifest);
    const token = await mintToken('https://unsafe-child.example.com/index.m3u8', { channel: 'unsafechild00001' });
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).not.toContain('#EXT-X-ENDLIST');
    expect(body).not.toContain('169.254.169.254');
    expect(body).not.toContain('/seg/');
  });

  it('inherits IP, MAC, user id, access-key id, and channel id into segment tokens', async () => {
    const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nbound.ts\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://bound.example.com').intercept({ path: '/index.m3u8' }).reply(200, manifest);
    await seedUser('manifest-binding-owner', 'password123');
    const owner = await env.DB.prepare("SELECT id FROM users WHERE username = 'manifest-binding-owner'").first<{ id: number }>();
    const marker = randomHex(32);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO access_keys
         (key_hash, key_prefix, label, username, user_id, status, max_devices, expires_at, created_at, updated_at)
       VALUES (?, ?, 'binding-test', 'manifest-binding-owner', ?, 'active', 1, NULL, ?, ?)`,
    )
      .bind(marker, marker.slice(0, 12), owner!.id, now, now)
      .run();
    const key = await env.DB.prepare('SELECT id FROM access_keys WHERE key_hash = ?').bind(marker).first<{ id: number }>();
    const token = await createToken(env.SECRET_KEY, {
      u: 'https://bound.example.com/index.m3u8',
      iat: now,
      exp: now + 300,
      k: 'm',
      c: 'boundchannel001x',
      ip: '198.51.100.7',
      mac: 'AA:BB:CC:DD:EE:FF',
      uid: owner!.id,
      aid: key!.id,
    });

    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`, {
      headers: { 'CF-Connecting-IP': '198.51.100.7' },
    });
    expect(res.status).toBe(200);
    const segmentUrl = (await res.text()).split('\n').find((line) => line.includes('/seg/'))!;
    const segmentToken = segmentUrl.match(/\/seg\/([^.]+)\.ts$/)![1]!;
    const segmentVerdict = await verifyToken(env.SECRET_KEY, segmentToken);
    expect(segmentVerdict.ok).toBe(true);
    if (segmentVerdict.ok) {
      expect(segmentVerdict.payload).toMatchObject({
        ip: '198.51.100.7',
        mac: 'AA:BB:CC:DD:EE:FF',
        uid: owner!.id,
        aid: key!.id,
        c: 'boundchannel001x',
        k: 's',
      });
    }

    const stolenSegment = await SELF.fetch(segmentUrl, {
      headers: { 'CF-Connecting-IP': '198.51.100.8' },
    });
    expect(stolenSegment.status).toBe(403);
    expect(((await stolenSegment.json()) as { error: string }).error).toBe('TOKEN_BINDING_MISMATCH');
  });

  it('resolves relative URIs against the FINAL URL after a redirect', async () => {
    const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nchunk1.ts\n#EXT-X-ENDLIST\n';
    const origin = fetchMock.get('https://up3.example.com');
    origin.intercept({ path: '/playlist.m3u8' }).reply(302, '', { headers: { Location: '/live/deep/index.m3u8' } });
    origin.intercept({ path: '/live/deep/index.m3u8' }).reply(200, manifest);

    const token = await mintToken('https://up3.example.com/playlist.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    const body = await res.text();
    const segUrl = body.split('\n').find((l) => l.includes('/seg/'))!;
    const segToken = segUrl.match(/\/seg\/([^.\n?]+)/)![1]!;
    const { verifyToken } = await import('../src/token');
    const verdict = await verifyToken(env.SECRET_KEY, segToken);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload.u).toBe('https://up3.example.com/live/deep/chunk1.ts');
  });

  it('gives slow relays the full 30s — a manifest answering past the old 8s cap is still proxied, no fallback', {
    timeout: 25_000,
  }, async () => {
    const manifest = '#EXTM3U\\n#EXT-X-TARGETDURATION:6\\n#EXTINF:6.0,\\nslow1.ts\\n#EXT-X-ENDLIST\\n';
    fetchMock
      .get('https://slowup.example.com')
      .intercept({ path: '/live/index.m3u8' })
      .reply(200, manifest)
      .delay(8_500); // dead under the old 8s manifest timeout; alive under the 30s policy

    const token = await mintToken('https://slowup.example.com/live/index.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBeNull();
    expect(await res.text()).toContain('#EXTM3U');
  });

  it('upstream 404 returns a valid CHRTV error manifest (not HTML)', async () => {
    fetchMock.get('https://dead1.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const token = await mintToken('https://dead1.example.com/gone.m3u8', { channel: 'deadchannel0001x' });
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain('#EXTM3U');
    expect(body).not.toContain('#EXT-X-ENDLIST');
    expect(body).not.toContain('dead1');
    // durable failure recorded for admin
    const failures = await env.DB.prepare("SELECT * FROM stream_failures WHERE channel_id = 'deadchannel0001x'").all();
    expect(failures.results.length).toBeGreaterThanOrEqual(1);
  });

  it('upstream 500 returns the error manifest', async () => {
    fetchMock.get('https://dead2.example.com').intercept({ path: '/err.m3u8' }).reply(500, 'boom');
    const token = await mintToken('https://dead2.example.com/err.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
  });

  it('unreachable upstream returns the error manifest', async () => {
    // No interceptor + disabled net connect => fetch throws
    const token = await mintToken('https://unreachable.example.com/x.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
  });

  it('non-HLS upstream body returns the error manifest', async () => {
    fetchMock.get('https://dead3.example.com').intercept({ path: '/html.m3u8' }).reply(200, '<html>oops</html>');
    const token = await mintToken('https://dead3.example.com/html.m3u8');
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    expect(await res.text()).not.toContain('<html>');
  });

  it('serves the configured FALLBACK_M3U_URL (re-proxied) when the upstream is dead', async () => {
    const fallbackManifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nfb.ts\n#EXT-X-ENDLIST\n';
    fetchMock
      .get('http://fallback.example.com')
      .intercept({ path: '/hls/index.m3u8' })
      .reply(200, fallbackManifest, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });
    fetchMock.get('https://deadfb.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');

    const token = await mintToken('https://deadfb.example.com/gone.m3u8', { channel: 'fbchannel000001x' });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      { ...env, FALLBACK_M3U_URL: 'http://fallback.example.com/hls/index.m3u8' },
      'req-fallback-123',
      token,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain(`${BASE}/seg/`);
    expect(body).not.toContain('fallback.example.com');
    expect(body).not.toContain('deadfb');
  });

  it('fails an unsupported-port primary over to a proxyable fallback without fetching or disclosing the primary', async () => {
    const primary = 'http://origin.example.com:30113/live/index.m3u8';
    const fallbackManifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nfallback.ts\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://strict-fallback.example.com').intercept({ path: '/index.m3u8' }).reply(200, fallbackManifest);
    const token = await mintToken(primary, { channel: 'strictfallback01x' });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      { ...env, FALLBACK_M3U_URL: 'https://strict-fallback.example.com/index.m3u8' },
      'req-strict-primary-fallback',
      token,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('Location')).toBeNull();
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain(`${BASE}/seg/`);
    expect(body).not.toContain(primary);
    expect(body).not.toContain('origin.example.com');
    expect(body).not.toContain('strict-fallback.example.com');
  });

  it('does not extend fallback descendant capabilities beyond the parent expiry', async () => {
    const fallbackManifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nfallback.ts\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://exp-fallback.example.com').intercept({ path: '/index.m3u8' }).reply(200, fallbackManifest);
    fetchMock.get('https://exp-dead.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const parentExpiry = Math.floor(Date.now() / 1000) + 45;
    const token = await mintToken('https://exp-dead.example.com/gone.m3u8', {
      channel: 'fallbackexpiry01x',
      exp: parentExpiry,
    });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      { ...env, FALLBACK_M3U_URL: 'https://exp-fallback.example.com/index.m3u8' },
      'req-fallback-expiry',
      token,
    );
    expect(res.status).toBe(200);
    const segmentUrl = (await res.text()).split('\n').find((line) => line.includes('/seg/'))!;
    const segmentToken = segmentUrl.match(/\/seg\/([^.]+)\.ts$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, segmentToken);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload.exp).toBe(parentExpiry);
  });

  it('skips an unsupported-port fallback without revealing its origin', async () => {
    fetchMock.get('https://deadport.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const token = await mintToken('https://deadport.example.com/gone.m3u8', { channel: 'portchannel0001x' });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      { ...env, FALLBACK_M3U_URL: 'http://chrtv.duckdns.org:30113/hls/index.m3u8' },
      'req-fallback-redirect',
      token,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('Location')).toBeNull();
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).not.toContain('#EXT-X-ENDLIST');
    expect(body).not.toContain('chrtv.duckdns.org');
    expect(body).not.toContain(':30113');
  });

  it('prefers a proxyable fallback over an unfetchable-port one', async () => {
    const fallbackManifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nfb2.ts\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://fb2.example.com').intercept({ path: '/hls/index.m3u8' }).reply(200, fallbackManifest);
    fetchMock.get('https://deadmulti.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');

    const token = await mintToken('https://deadmulti.example.com/gone.m3u8', { channel: 'multichannel001x' });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      {
        ...env,
        FALLBACK_M3U_URL: 'https://fb2.example.com/hls/index.m3u8, http://chrtv.duckdns.org:30113/hls/index.m3u8',
      },
      'req-fallback-multi',
      token,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain(`${BASE}/seg/`);
    expect(body).not.toContain('fb2.example.com');
  });

  it('fails closed when proxyable fallbacks are dead and remaining ports are unsupported', async () => {
    fetchMock.get('https://fb3.example.com').intercept({ path: '/hls/index.m3u8' }).reply(500, 'boom');
    fetchMock.get('https://deadchain.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');

    const token = await mintToken('https://deadchain.example.com/gone.m3u8', { channel: 'chainchannel001x' });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`),
      {
        ...env,
        FALLBACK_M3U_URL: 'https://fb3.example.com/hls/index.m3u8 http://chrtv.duckdns.org:30113/hls/index.m3u8',
      },
      'req-fallback-chain',
      token,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('Location')).toBeNull();
    const body = await res.text();
    expect(body).not.toContain('#EXT-X-ENDLIST');
    expect(body).not.toContain('chrtv.duckdns.org');
    expect(body).not.toContain(':30113');
  });

  it('falls back to the empty error manifest when FALLBACK_M3U_URL is unset', async () => {
    fetchMock.get('https://deadnb.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const token = await mintToken('https://deadnb.example.com/gone.m3u8', { channel: 'nbchannel000001x' });
    const res = await handleHlsManifest(new Request(`${BASE}/hls/${token}.m3u8`), env, 'req-nofallback-123', token);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).not.toContain('#EXT-X-ENDLIST');
    expect(body).not.toContain('/seg/');
  });

  it('circuit breaker short-circuits repeated requests to a dead channel', async () => {
    fetchMock.get('https://dead4.example.com').intercept({ path: '/cb.m3u8' }).reply(503, 'unavailable');
    const token = await mintToken('https://dead4.example.com/cb.m3u8', { channel: 'cbchannel000001x' });
    const first = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(first.headers.get('X-CHRTV-Fallback')).toBe('1');
    // Second request: no interceptor registered => would throw if fetched.
    // The breaker must answer from cache without touching the upstream.
    const second = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(second.status).toBe(200);
    expect(second.headers.get('X-CHRTV-Fallback')).toBe('1');
  });

  it('/live/{user}/{pass}/{id}.m3u8 exchanges credentials for an opaque live URL', async () => {
    await seedChannels();
    await seedUser('bob', 'password123');
    const res = await SELF.fetch(`${BASE}/live/bob/password123/100001.m3u8`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    expect(location).toMatch(/^https:\/\/chrtv\.example\.com\/hls\/.+\.m3u8$/);
    expect(location).not.toContain('bob');
    expect(location).not.toContain('password123');
    expect(location).not.toContain('up.example.com');
    const token = location.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload.u).toBe('https://up.example.com/live/vtv1/index.m3u8');

    const bad = await SELF.fetch(`${BASE}/live/bob/wrongpass/100001.m3u8`, { redirect: 'manual' });
    expect(bad.status).toBe(401);
    const missing = await SELF.fetch(`${BASE}/live/bob/password123/999999.m3u8`, { redirect: 'manual' });
    expect(missing.status).toBe(404);
  });

  it('the bare /{user}/{pass}/{id} form also redirects to an opaque URL', async () => {
    await seedChannels();
    await seedUser('bareuser', 'barepass123');
    const res = await SELF.fetch(`${BASE}/bareuser/barepass123/100002.m3u8`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toMatch(/^https:\/\/chrtv\.example\.com\/hls\/.+\.m3u8$/);
  });

  it('does not let the bare live route shadow the admin API or other routes', async () => {
    const admin = await SELF.fetch(`${BASE}/api/admin/status`, { headers: ADMIN });
    expect(admin.status).toBe(200);
    const notFound = await SELF.fetch(`${BASE}/some/random/path`);
    expect(notFound.status).toBe(404);
  });

  it('/live/{user}/{pass}/{id}.m3u8 keeps custom-port channel origins hidden', async () => {
    await seedChannels();
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT OR REPLACE INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
       VALUES ('aaaaaaaaaaaaaaa4', 100004, 'HBO Live', 'http://chrtv.duckdns.org:18483/stream/cg_hbofam/index.m3u8', 'hbo-live', '', 1, 3, 1, 1, ?, ?)`,
    ).bind(now, now).run();
    await seedUser('bob', 'password123');

    const res = await SELF.fetch(`${BASE}/live/bob/password123/100004.m3u8`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    const opaque = res.headers.get('Location')!;
    expect(opaque).toMatch(/^https:\/\/chrtv\.example\.com\/hls\/.+\.m3u8$/);
    const stream = await SELF.fetch(opaque, { redirect: 'manual' });
    expect(stream.status).toBe(200);
    expect(stream.headers.get('Location')).toBeNull();
    const body = await stream.text();
    expect(body).toContain('#EXTM3U');
    expect(body).not.toContain('#EXT-X-ENDLIST'); // live fallback: player keeps retrying
    expect(body).not.toContain('chrtv.duckdns.org');
    expect(body).not.toContain(':18483');
  });
});

describe('media segment proxy', () => {
  it('streams a segment and preserves content headers', async () => {
    fetchMock
      .get('https://seg1.example.com')
      .intercept({ path: '/s.ts' })
      .reply(200, 'FAKE-TS-DATA', {
        headers: { 'Content-Type': 'video/mp2t', ETag: '"abc123"', 'Last-Modified': 'Mon, 01 Jan 2024 00:00:00 GMT' },
      });
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(env.SECRET_KEY, { u: 'https://seg1.example.com/s.ts', iat: now, exp: now + 300, k: 's' });
    const res = await SELF.fetch(`${BASE}/seg/${token}.ts`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('video/mp2t');
    expect(res.headers.get('ETag')).toBe('"abc123"');
    expect(res.headers.get('Last-Modified')).toContain('2024');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(await res.text()).toBe('FAKE-TS-DATA');
  });

  it('forwards Range and preserves 206 + Content-Range', async () => {
    fetchMock
      .get('https://seg2.example.com')
      .intercept({ path: '/r.mp4', headers: { range: 'bytes=0-3' } })
      .reply(206, 'ABCD', { headers: { 'Content-Range': 'bytes 0-3/100', 'Content-Type': 'video/mp4' } });
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(env.SECRET_KEY, { u: 'https://seg2.example.com/r.mp4', iat: now, exp: now + 300, k: 's' });
    const res = await SELF.fetch(`${BASE}/seg/${token}.mp4`, { headers: { Range: 'bytes=0-3' } });
    expect(res.status).toBe(206);
    expect(res.headers.get('Content-Range')).toBe('bytes 0-3/100');
    expect(await res.text()).toBe('ABCD');
  });

  it('upstream media failure returns a real HTTP error, never HTML', async () => {
    fetchMock.get('https://seg3.example.com').intercept({ path: '/gone.ts' }).reply(404, 'x');
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(env.SECRET_KEY, { u: 'https://seg3.example.com/gone.ts', iat: now, exp: now + 300, k: 's' });
    const res = await SELF.fetch(`${BASE}/seg/${token}.ts`);
    expect(res.status).toBe(502);
    expect(res.headers.get('Content-Type')).toContain('json');
  });

  it('fails closed for unsupported-port media without a raw Location header', async () => {
    const upstream = 'http://origin.example.com:30113/media/segment.ts';
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(env.SECRET_KEY, { u: upstream, iat: now, exp: now + 300, k: 's' });
    const res = await SELF.fetch(`${BASE}/seg/${token}.ts`, { redirect: 'manual' });
    expect(res.status).toBe(502);
    expect(res.headers.get('Location')).toBeNull();
    const body = await res.text();
    expect(body).not.toContain(upstream);
    expect(body).not.toContain('origin.example.com');
  });

  it('rejects invalid segment tokens with 403', async () => {
    const res = await SELF.fetch(`${BASE}/seg/garbage.ts`);
    expect(res.status).toBe(403);
  });
});

describe('playlist sync', () => {
  const PLAYLIST_HOST = 'https://raw.example.com';
  const PLAYLIST_PATH = '/playlists/tv.m3u';

  const goodPlaylist = [
    '#EXTM3U',
    '#EXTINF:-1 tvg-id="c1" group-title="News",Channel One',
    'https://s1.example.com/one.m3u8',
    '#EXTINF:-1 tvg-id="c2" group-title="Sports",Channel Two',
    'https://s1.example.com/two.m3u8',
  ].join('\n');

  it('syncs a playlist into D1, skips when unchanged, keeps old data on bad sync', async () => {
    // reset sync state
    await env.DB.batch([
      env.DB.prepare("UPDATE settings SET value = '' WHERE key IN ('playlist_hash','sync_lock')"),
      env.DB.prepare("UPDATE settings SET value = '0' WHERE key = 'sync_seq'"),
    ]);

    // 1) initial sync
    fetchMock.get(PLAYLIST_HOST).intercept({ path: PLAYLIST_PATH }).reply(200, goodPlaylist);
    const r1 = await syncPlaylist(env, 'admin');
    expect(r1.status).toBe('ok');
    expect(r1.channelCount).toBe(2);
    const c1 = await env.DB.prepare("SELECT * FROM channels WHERE name = 'Channel One' AND active = 1").first();
    expect(c1).toBeTruthy();

    // 2) unchanged => skipped, no rewrite
    fetchMock.get(PLAYLIST_HOST).intercept({ path: PLAYLIST_PATH }).reply(200, goodPlaylist);
    const r2 = await syncPlaylist(env, 'admin');
    expect(r2.status).toBe('skipped');

    // 3) broken playlist => failed, old channels stay live
    fetchMock.get(PLAYLIST_HOST).intercept({ path: PLAYLIST_PATH }).reply(200, 'GARBAGE NOT M3U');
    const r3 = await syncPlaylist(env, 'admin');
    expect(r3.status).toBe('failed');
    const stillThere = await env.DB.prepare("SELECT COUNT(*) AS n FROM channels WHERE active = 1 AND name LIKE 'Channel%'").first<{ n: number }>();
    expect(stillThere?.n).toBe(2);

    // 4) updated playlist => channel removed gets deactivated, ids stay stable
    const updated = goodPlaylist.split('\n').slice(0, 3).join('\n'); // only Channel One remains
    fetchMock.get(PLAYLIST_HOST).intercept({ path: PLAYLIST_PATH }).reply(200, updated);
    const r4 = await syncPlaylist(env, 'admin');
    expect(r4.status).toBe('ok');
    const two = await env.DB.prepare("SELECT active FROM channels WHERE name = 'Channel Two'").first<{ active: number }>();
    expect(two?.active).toBe(0);
    const oneAfter = await env.DB.prepare("SELECT id FROM channels WHERE name = 'Channel One'").first<{ id: string }>();
    const oneBefore = c1 as { id: string };
    expect(oneAfter?.id).toBe(oneBefore.id);

    // sync logs recorded
    const logs = await env.DB.prepare('SELECT status FROM sync_logs ORDER BY id DESC LIMIT 4').all<{ status: string }>();
    expect(logs.results.map((l) => l.status)).toEqual(['ok', 'failed', 'skipped', 'ok']);
  });

  it('admin can trigger sync over HTTP', async () => {
    fetchMock.get(PLAYLIST_HOST).intercept({ path: PLAYLIST_PATH }).reply(200, goodPlaylist);
    const res = await SELF.fetch(`${BASE}/api/admin/sync`, { method: 'POST', headers: ADMIN });
    expect([200, 409]).toContain(res.status);
  });

  it('unreachable playlist source marks sync failed without touching data', async () => {
    const before = await env.DB.prepare('SELECT COUNT(*) AS n FROM channels WHERE active = 1').first<{ n: number }>();
    // no interceptor => fetch fails
    const r = await syncPlaylist(env, 'cron');
    expect(r.status).toBe('failed');
    const after = await env.DB.prepare('SELECT COUNT(*) AS n FROM channels WHERE active = 1').first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
  });
});

describe('EPG', () => {
  it('serves XMLTV only through a dedicated token exposed by M3U', async () => {
    await seedChannels();
    const ip = '192.0.2.241';
    const playlist = await SELF.fetch(`${BASE}/tv.m3u`, { headers: { 'CF-Connecting-IP': ip } });
    const text = await playlist.text();
    const epgUrl = text.match(/url-tvg="([^"]+)"/)![1]!;
    expect(epgUrl).toMatch(/^https:\/\/chrtv\.example\.com\/epg\/.+\.xml$/);
    expect(epgUrl).not.toContain('epg.io.vn');
    const token = epgUrl.match(/\/epg\/([^.]+)\.xml$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.payload).toMatchObject({ k: 'e', ip });

    const res = await SELF.fetch(epgUrl, { headers: { 'CF-Connecting-IP': ip } });
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('xml');
    const body = await res.text();
    expect(body).toContain('<?xml');
    expect(body).toContain('<tv');
    expect(body).toContain('</tv>');
  });

  it('rejects media-token substitution and exchanges valid Xtream credentials for an EPG token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const media = await createToken(env.SECRET_KEY, {
      u: 'https://epg-token.chrtv.invalid/xmltv.xml', iat: now, exp: now + 300, k: 'm',
    });
    expect((await SELF.fetch(`${BASE}/epg/${media}.xml`)).status).toBe(403);
    expect((await SELF.fetch(`${BASE}/xmltv.php`)).status).toBe(401);

    await seedUser('epguser', 'epgpass123');
    const redirect = await SELF.fetch(`${BASE}/xmltv.php?username=epguser&password=epgpass123`, { redirect: 'manual' });
    expect(redirect.status).toBe(302);
    expect(redirect.headers.get('Location')).toMatch(/^https:\/\/chrtv\.example\.com\/epg\/.+\.xml$/);
  });
});

// ---------------------------------------------------------------------------
// Channel health checks (proactive offline detection).
// These suites run last and reset the channel table to a known state because
// healthCheckBatch selects across ALL active channels — leftovers from earlier
// tests would otherwise change the counts and trigger unexpected fetches.
// ---------------------------------------------------------------------------

const HLS_OK = '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\ns.ts\n#EXT-X-ENDLIST\n';

async function resetChannels(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM channel_health'),
    env.DB.prepare('DELETE FROM channels'),
    env.DB.prepare("INSERT OR IGNORE INTO categories (name, position) VALUES ('News', 0)"),
  ]);
}

describe('channel health probe', () => {
  it('classifies a live HLS upstream as online', async () => {
    fetchMock
      .get('https://hprobe.example.com')
      .intercept({ path: '/ok.m3u8' })
      .reply(200, HLS_OK, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });
    const r = await probeChannel('https://hprobe.example.com/ok.m3u8');
    expect(r).toEqual({ status: 'online', errorCode: '', httpStatus: 200 });
  });

  it('flags a 404 upstream as offline', async () => {
    fetchMock.get('https://hprobe.example.com').intercept({ path: '/404.m3u8' }).reply(404, 'x');
    const r = await probeChannel('https://hprobe.example.com/404.m3u8');
    expect(r).toMatchObject({ status: 'offline', errorCode: 'UPSTREAM_404', httpStatus: 404 });
  });

  it('keeps a 200 + HTML body as unknown — the link IS reachable, just serving non-HLS (anti-bot page)', async () => {
    fetchMock.get('https://hprobe.example.com').intercept({ path: '/html.m3u8' }).reply(200, '<html><body>down</body></html>');
    const r = await probeChannel('https://hprobe.example.com/html.m3u8');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'INVALID_HLS', httpStatus: 200 });
  });

  it('keeps a 5xx upstream as unknown — the server answered, the link is not dead', async () => {
    fetchMock.get('https://hprobe.example.com').intercept({ path: '/500.m3u8' }).reply(500, 'boom');
    const r = await probeChannel('https://hprobe.example.com/500.m3u8');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UPSTREAM_5XX', httpStatus: 500 });
  });

  it('keeps a 403 (auth/geo-block) as unknown — the probe vantage cannot judge it', async () => {
    fetchMock.get('https://hprobe.example.com').intercept({ path: '/403.m3u8' }).reply(403, 'Forbidden');
    const r = await probeChannel('https://hprobe.example.com/403.m3u8');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UPSTREAM_4XX', httpStatus: 403 });
  });

  it('keeps a 429 (rate-limit) as unknown instead of false-flagging offline', async () => {
    fetchMock.get('https://hprobe.example.com').intercept({ path: '/429.m3u8' }).reply(429, 'slow down');
    const r = await probeChannel('https://hprobe.example.com/429.m3u8');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UPSTREAM_4XX', httpStatus: 429 });
  });

  it('follows a redirect chain that ends in a 403 → unknown (not offline)', async () => {
    const origin = fetchMock.get('https://hprobe-redir2.example.com');
    origin.intercept({ path: '/go' }).reply(302, '', { headers: { Location: '/blocked.m3u8' } });
    origin.intercept({ path: '/blocked.m3u8' }).reply(403, 'Forbidden');
    const r = await probeChannel('https://hprobe-redir2.example.com/go');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UPSTREAM_4XX', httpStatus: 403 });
  });

  it('flags an unreachable upstream as offline (no interceptor => fetch throws)', async () => {
    const r = await probeChannel('https://hprobe-unreachable.example.com/x.m3u8');
    expect(r).toMatchObject({ status: 'offline', errorCode: 'UPSTREAM_UNREACHABLE' });
  });

  it('marks a channel on a Workers-unfetchable port as unknown without fetching it', async () => {
    const r = await probeChannel('http://hprobe.example.com:30113/x.m3u8');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UNSUPPORTED_PORT' });
  });

  it('marks an unsafe upstream as unknown without fetching', async () => {
    const r = await probeChannel('http://169.254.169.254/latest/meta-data');
    expect(r).toMatchObject({ status: 'unknown', errorCode: 'UNSAFE_URL' });
  });

  it('follows a redirect to a live manifest', async () => {
    const origin = fetchMock.get('https://hprobe-redir.example.com');
    origin.intercept({ path: '/go' }).reply(302, '', { headers: { Location: '/final/index.m3u8' } });
    origin.intercept({ path: '/final/index.m3u8' }).reply(200, HLS_OK);
    const r = await probeChannel('https://hprobe-redir.example.com/go');
    expect(r).toMatchObject({ status: 'online', httpStatus: 200 });
  });

  it('does NOT flag a slow relay offline — answers past the old 6s cap are still online', {
    timeout: 25_000,
  }, async () => {
    // devda-style relay: first byte takes ~10-25s. Under the old 6s probe
    // timeout this was flagged offline on every sweep; policy is now 30s.
    fetchMock.get('https://hprobe-slow.example.com').intercept({ path: '/slow.m3u8' }).reply(200, HLS_OK).delay(7_000);
    const r = await probeChannel('https://hprobe-slow.example.com/slow.m3u8');
    expect(r).toMatchObject({ status: 'online', httpStatus: 200 });
  });
});

describe('health-check sweep', () => {
  async function seedSweepChannels(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('cafebabe00000001', 200001, 'H-Online', 'https://hsweep.example.com/online.m3u8', '', '', 1, 0, 1, 9, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('cafebabe00000002', 200002, 'H-Dead', 'https://hsweep.example.com/dead.m3u8', '', '', 1, 1, 1, 9, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('cafebabe00000003', 200003, 'H-HTML', 'https://hsweep.example.com/html.m3u8', '', '', 1, 2, 1, 9, ?, ?)`,
      ).bind(now, now),
    ]);
  }

  it('probes a batch and records per-channel health — offline only after 2 consecutive unreachable probes', async () => {
    await seedSweepChannels();
    const origin = fetchMock.get('https://hsweep.example.com');
    origin.intercept({ path: '/online.m3u8' }).reply(200, HLS_OK).persist();
    origin.intercept({ path: '/dead.m3u8' }).reply(404, 'x').persist();
    origin.intercept({ path: '/html.m3u8' }).reply(200, '<html>down</html>').persist();

    // Sweep 1: the dead link fails once => still `unknown` (needs confirmation);
    // the HTML link is reachable => `unknown` too, never offline.
    const first = await healthCheckBatch(env, 10);
    expect(first).toEqual({ checked: 3, online: 1, offline: 0, unknown: 2 });

    let rows = await env.DB
      .prepare("SELECT channel_id, status, error_code, fail_streak FROM channel_health WHERE channel_id LIKE 'cafebabe%' ORDER BY channel_id")
      .all<{ channel_id: string; status: string; error_code: string; fail_streak: number }>();
    let byId = Object.fromEntries(rows.results.map((r) => [r.channel_id, r]));
    expect(byId['cafebabe00000001']).toMatchObject({ status: 'online', fail_streak: 0 });
    expect(byId['cafebabe00000002']).toMatchObject({ status: 'unknown', error_code: 'UPSTREAM_404', fail_streak: 1 });
    expect(byId['cafebabe00000003']).toMatchObject({ status: 'unknown', error_code: 'INVALID_HLS', fail_streak: 0 });

    // Sweep 2: the dead link fails a second consecutive time => confirmed offline.
    const second = await healthCheckBatch(env, 10);
    expect(second).toEqual({ checked: 3, online: 1, offline: 1, unknown: 1 });

    rows = await env.DB
      .prepare("SELECT channel_id, status, error_code, fail_streak FROM channel_health WHERE channel_id LIKE 'cafebabe%' ORDER BY channel_id")
      .all<{ channel_id: string; status: string; error_code: string; fail_streak: number }>();
    byId = Object.fromEntries(rows.results.map((r) => [r.channel_id, r]));
    expect(byId['cafebabe00000002']).toMatchObject({ status: 'offline', error_code: 'UPSTREAM_404', fail_streak: 2 });
    expect(byId['cafebabe00000003']).toMatchObject({ status: 'unknown', error_code: 'INVALID_HLS' });
  });

  it('a recovery between failures resets the streak — flapping never reaches offline', async () => {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('cafebabe00000042', 200042, 'H-Flap', 'https://hflap.example.com/ch.m3u8', '', '', 1, 0, 1, 9, ?, ?)`,
      ).bind(now, now),
    ]);
    const origin = fetchMock.get('https://hflap.example.com');

    // fail (streak 1 → unknown)
    origin.intercept({ path: '/ch.m3u8' }).reply(404, 'x');
    await healthCheckBatch(env, 10);
    // recover (streak reset)
    origin.intercept({ path: '/ch.m3u8' }).reply(200, HLS_OK);
    await healthCheckBatch(env, 10);
    // fail again (streak back to 1 → still unknown, NOT offline)
    origin.intercept({ path: '/ch.m3u8' }).reply(404, 'x');
    const summary = await healthCheckBatch(env, 10);
    expect(summary.offline).toBe(0);

    const row = await env.DB
      .prepare("SELECT status, fail_streak FROM channel_health WHERE channel_id = 'cafebabe00000042'")
      .first<{ status: string; fail_streak: number }>();
    expect(row).toMatchObject({ status: 'unknown', fail_streak: 1 });
  });

  it('sweeps the oldest-checked channels first (never-checked beats recently checked)', async () => {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('facade00000000a', 200011, 'Fresh', 'https://hsweep.example.com/fresh.m3u8', '', '', 1, 0, 1, 9, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('facade00000000b', 200012, 'Stale', 'https://hsweep.example.com/stale.m3u8', '', '', 1, 1, 1, 9, ?, ?)`,
      ).bind(now, now),
      // Stale was already checked recently; Fresh has never been checked.
      env.DB.prepare(
        "INSERT INTO channel_health (channel_id, status, error_code, http_status, checked_at) VALUES ('facade00000000b', 'online', '', 200, ?)",
      ).bind(now),
    ]);
    // Only register an interceptor for Fresh — limit=1 must pick it (oldest = NULL).
    fetchMock.get('https://hsweep.example.com').intercept({ path: '/fresh.m3u8' }).reply(200, HLS_OK);

    const summary = await healthCheckBatch(env, 1);
    expect(summary.checked).toBe(1);
    const fresh = await env.DB
      .prepare("SELECT checked_at FROM channel_health WHERE channel_id = 'facade00000000a'")
      .first<{ checked_at: number }>();
    expect(fresh?.checked_at).toBeGreaterThan(0);
  });

  it('caps every sweep at MAX_PROBES_PER_RUN so Free-plan subrequest limits can never flood false offlines', async () => {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 15; i++) {
      const id = `cafebabe000001${String(i).padStart(2, '0')}`;
      stmts.push(
        env.DB.prepare(
          `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
           VALUES (?, ?, ?, ?, '', '', 1, ?, 1, 9, ?, ?)`,
        ).bind(id, 210000 + i, `C${i}`, `https://hcap.example.com/c${i}.m3u8`, i, now, now),
      );
    }
    await env.DB.batch(stmts);
    // No interceptors: every probe throws immediately (unreachable). A request
    // past the 50-subrequest ceiling would do the same — the point is that the
    // sweep must never run enough fetches to reach it.
    const summary = await healthCheckBatch(env, 100);
    expect(summary.checked).toBe(MAX_PROBES_PER_RUN);
    expect(summary.checked).toBeLessThanOrEqual(12);
    const { results } = await env.DB.prepare('SELECT COUNT(*) AS n FROM channel_health').all<{ n: number }>();
    expect(results[0]?.n).toBe(MAX_PROBES_PER_RUN);
  });
});

describe('admin health visibility', () => {
  async function seedHealthState(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('deadbeef00000001', 300001, 'Offline One', 'https://x.example.com/a.m3u8', '', '', 1, 0, 1, 1, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('deadbeef00000002', 300002, 'Online One', 'https://x.example.com/b.m3u8', '', '', 1, 1, 1, 1, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        'INSERT INTO channel_health (channel_id, status, error_code, http_status, checked_at) VALUES (?, ?, ?, ?, ?)',
      )
        .bind('deadbeef00000001', 'offline', 'UPSTREAM_404', 404, now),
      env.DB.prepare(
        'INSERT INTO channel_health (channel_id, status, error_code, http_status, checked_at) VALUES (?, ?, ?, ?, ?)',
      )
        .bind('deadbeef00000002', 'online', '', 200, now),
    ]);
  }

  it('GET /api/admin/offline lists only the offline channels', async () => {
    await seedHealthState();
    const res = await SELF.fetch(`${BASE}/api/admin/offline`, { headers: ADMIN });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { count: number; channels: Array<{ name: string; error_code: string }> };
    expect(body.count).toBe(1);
    expect(body.channels[0]).toMatchObject({ name: 'Offline One', error_code: 'UPSTREAM_404' });
  });

  it('GET /api/admin/offline requires admin auth', async () => {
    const res = await SELF.fetch(`${BASE}/api/admin/offline`);
    expect(res.status).toBe(401);
  });

  it('GET /api/admin/channels surfaces health_status per channel', async () => {
    await seedHealthState();
    const res = await SELF.fetch(`${BASE}/api/admin/channels`, { headers: ADMIN });
    expect(res.status).toBe(200);
    const list = (await res.json()) as Array<{ name: string; health_status: string | null; error_code: string | null }>;
    const off = list.find((c) => c.name === 'Offline One')!;
    const on = list.find((c) => c.name === 'Online One')!;
    expect(off.health_status).toBe('offline');
    expect(off.error_code).toBe('UPSTREAM_404');
    expect(on.health_status).toBe('online');
  });

  it('GET /api/admin/status includes a health summary with the offline count', async () => {
    await seedHealthState();
    const res = await SELF.fetch(`${BASE}/api/admin/status`, { headers: ADMIN });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { health: { online: number; offline: number; unknown: number; offline_ratio: number } };
    expect(body.health).toMatchObject({ online: 1, offline: 1, unknown: 0, offline_ratio: 50 });
  });

  it('POST /api/admin/health-check runs a sweep and returns the summary', async () => {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('beef000000000001', 300011, 'Live', 'https://hc.example.com/live.m3u8', '', '', 1, 0, 1, 1, ?, ?)`,
      ).bind(now, now),
      env.DB.prepare(
        `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
         VALUES ('beef000000000002', 300012, 'Dead', 'https://hc.example.com/dead.m3u8', '', '', 1, 1, 1, 1, ?, ?)`,
      ).bind(now, now),
    ]);
    const origin = fetchMock.get('https://hc.example.com');
    origin.intercept({ path: '/live.m3u8' }).reply(200, HLS_OK).persist();
    // 404 = the link itself is gone (a 5xx would only be `unknown` now).
    origin.intercept({ path: '/dead.m3u8' }).reply(404, 'gone').persist();

    // First sweep: dead link is only suspect (unknown, streak 1).
    const first = await SELF.fetch(`${BASE}/api/admin/health-check`, { method: 'POST', headers: ADMIN });
    expect(first.status).toBe(200);
    const s1 = (await first.json()) as { checked: number; online: number; offline: number; unknown: number };
    expect(s1).toMatchObject({ checked: 2, online: 1, offline: 0, unknown: 1 });

    // Second sweep: second consecutive failure confirms it offline.
    const res = await SELF.fetch(`${BASE}/api/admin/health-check`, { method: 'POST', headers: ADMIN });
    expect(res.status).toBe(200);
    const summary = (await res.json()) as { checked: number; online: number; offline: number };
    expect(summary).toMatchObject({ checked: 2, online: 1, offline: 1 });
    // Offline channel now appears in /offline.
    const off = await SELF.fetch(`${BASE}/api/admin/offline`, { headers: ADMIN });
    const offBody = (await off.json()) as { count: number };
    expect(offBody.count).toBe(1);
  });

  it('GET /api/admin/health-check is not allowed (POST only)', async () => {
    const res = await SELF.fetch(`${BASE}/api/admin/health-check`, { headers: ADMIN });
    expect(res.status).toBe(405);
  });
});

describe('web player /xem', () => {
  it('serves the player page with a strict CSP and its same-origin script', async () => {
    const res = await SELF.fetch(`${BASE}/xem`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/html');
    const csp = res.headers.get('Content-Security-Policy') ?? '';
    expect(csp).toContain("script-src 'self' https://cdn.jsdelivr.net");
    expect(csp).toContain("connect-src 'self'");
    const body = await res.text();
    expect(body).toContain('/ui/player.js');
    expect(body).toContain('cdn.jsdelivr.net/npm/hls.js');
    expect(body).toContain('id="paste-url"'); // paste-and-play box for token links
    expect(body).toContain('id="video"');

    const js = await SELF.fetch(`${BASE}/ui/player.js`);
    expect(js.status).toBe(200);
    expect(js.headers.get('Content-Type')).toContain('javascript');
    const script = await js.text();
    expect(script).toContain("fetch('/api/channels'");
    expect(script).not.toContain('SECRET');
  });

  it('the landing page links to the web player', async () => {
    const res = await SELF.fetch(`${BASE}/`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('href="/xem"');
  });

  it('GET /api/channels returns the same tokenized entries as /tv.m3u without leaking upstreams', async () => {
    await seedChannels();
    const ip = '192.0.2.77';
    const res = await SELF.fetch(`${BASE}/api/channels`, { headers: { 'CF-Connecting-IP': ip } });
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('application/json');
    const raw = await res.text();
    expect(raw).not.toContain('up.example.com'); // upstream never exposed
    const body = JSON.parse(raw) as { count: number; epg: string; channels: Array<{ id: string; name: string; group: string; url: string }> };
    expect(body.count).toBeGreaterThanOrEqual(2);
    expect(body.epg).toContain(`${BASE}/epg/`);
    const vtv1 = body.channels.find((c) => c.name === 'VTV1')!;
    expect(vtv1.group).toBe('News');
    expect(vtv1.url.startsWith(`${BASE}/hls/`)).toBe(true);
    const token = vtv1.url.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.payload).toMatchObject({ u: 'https://up.example.com/live/vtv1/index.m3u8', k: 'm', c: 'aaaaaaaaaaaaaaa1', ip });
    }
    const event = await env.DB.prepare(
      "SELECT event_type, route, outcome FROM auth_events WHERE route = '/api/channels' ORDER BY id DESC LIMIT 1",
    ).first<{ event_type: string; route: string; outcome: string }>();
    expect(event).toEqual({ event_type: 'playlist', route: '/api/channels', outcome: 'success' });
  });

  it('rejects wrong methods on the player APIs', async () => {
    expect((await SELF.fetch(`${BASE}/api/channels`, { method: 'POST' })).status).toBe(405);
    expect((await SELF.fetch(`${BASE}/api/play`)).status).toBe(405);
  });

  it('POST /api/play mints a playable proxy manifest for a ?token= link and proxies its media', async () => {
    const manifest = [
      '#EXTM3U',
      '#EXT-X-VERSION:3',
      '#EXT-X-TARGETDURATION:6',
      '#EXTINF:6.0,',
      'seg001.ts',
      '#EXT-X-ENDLIST',
    ].join('\n');
    fetchMock
      .get('https://playtok.example.com')
      .intercept({ path: /\/api\/stream\/GETftplay\/SEJP\/index\.m3u8/ })
      .reply(200, manifest, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });

    const pasted = 'https://playtok.example.com/api/stream/GETftplay/SEJP/index.m3u8?token=snYheZmfoT3BDCfcS8k4FNfCJbel4iveQYtx7ZMH';
    const ip = '203.0.113.9';
    const res = await SELF.fetch(`${BASE}/api/play`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
      body: JSON.stringify({ url: pasted }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { src: string; expires_at: number };
    expect(body.src.startsWith(`${BASE}/hls/`)).toBe(true);
    expect(body.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    // The pasted upstream URL (query token included) travels only inside the token.
    expect(JSON.stringify(body)).not.toContain('playtok.example.com');

    const token = body.src.match(/\/hls\/([^.]+)\.m3u8$/)![1]!;
    const verdict = await verifyToken(env.SECRET_KEY, token);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.payload.u).toBe(pasted); // ?token=… preserved end to end
      expect(verdict.payload.k).toBe('m');
    }

    // Identity binding holds: same IP plays, a different IP is rejected.
    const play = await SELF.fetch(body.src, { headers: { 'CF-Connecting-IP': ip } });
    expect(play.status).toBe(200);
    const played = await play.text();
    expect(played).toContain(`${BASE}/seg/`);
    expect(played).not.toContain('playtok.example.com');

    const stolen = await SELF.fetch(body.src, { headers: { 'CF-Connecting-IP': '203.0.113.10' } });
    expect(stolen.status).toBe(403);
  });

  it('POST /api/play rejects unsafe URLs, unsupported ports, and junk payloads', async () => {
    const cases: Array<[string, string]> = [
      ['http://127.0.0.1/x.m3u8', 'UNSAFE_URL'],
      ['https://localhost/live.m3u8', 'UNSAFE_URL'],
      ['http://169.254.169.254/latest/meta-data', 'UNSAFE_URL'],
      ['http://chrtv.duckdns.org:30113/hls/master.m3u8', 'UNSUPPORTED_PORT'],
      ['not a url', 'UNSAFE_URL'],
    ];
    for (const [url, code] of cases) {
      const res = await SELF.fetch(`${BASE}/api/play`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(code);
    }
    for (const body of ['{', '{"url":123}', '{}']) {
      const res = await SELF.fetch(`${BASE}/api/play`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      expect(res.status).toBe(400);
    }
  });
});

// ---------------------------------------------------------------------------
// Personal credential links, client-IP forwarding opt-in, live fallback
// ---------------------------------------------------------------------------

describe('credential-bearing personal links', () => {
  // Storage is isolated per test — each case seeds its own channel row.
  async function seedTokenChannel(id: string, xtreamId: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await resetChannels();
    await env.DB.prepare(
      `INSERT INTO channels (id, xtream_id, name, url, tvg_id, tvg_logo, category_id, position, active, sync_seq, created_at, updated_at)
       VALUES (?, ?, 'H-Token', 'https://htoken.example.com/api/stream/CH/index.m3u8?token=abcdef123456', '', '', 1, 0, 1, 9, ?, ?)`,
    )
      .bind(id, xtreamId, now, now)
      .run();
  }

  it('health sweep NEVER pings a ?token= channel (random-colo probes trip relay anti-abuse)', async () => {
    await seedTokenChannel('cafebabe00000099', 200099);
    // No interceptor is registered and disableNetConnect() is active: if the
    // sweep fetched anyway, the probe would fail with an UPSTREAM_* code —
    // never PERSONAL_LINK — and the assertions below would expose it.
    const summary = await healthCheckBatch(env, 10);
    expect(summary).toEqual({ checked: 1, online: 0, offline: 0, unknown: 1 });
    const row = await env.DB
      .prepare("SELECT status, error_code, fail_streak, checked_at FROM channel_health WHERE channel_id = 'cafebabe00000099'")
      .first<{ status: string; error_code: string; fail_streak: number; checked_at: number }>();
    expect(row).toMatchObject({ status: 'unknown', error_code: 'PERSONAL_LINK', fail_streak: 0 });
    // Marked checked, so the rotation does not keep selecting the same
    // unprobeable channels on every sweep.
    expect(row!.checked_at).toBeGreaterThan(0);
  });

  it('HEALTH_PROBE_CREDENTIAL_LINKS=true opts back into probing token links', async () => {
    await seedTokenChannel('cafebabe00000098', 200098);
    fetchMock
      .get('https://htoken.example.com')
      .intercept({ path: '/api/stream/CH/index.m3u8?token=abcdef123456' })
      .reply(200, HLS_OK, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });
    const summary = await healthCheckBatch({ ...env, HEALTH_PROBE_CREDENTIAL_LINKS: 'true' }, 10);
    expect(summary).toEqual({ checked: 1, online: 1, offline: 0, unknown: 0 });
  });
});

describe('upstream client-IP forwarding (opt-in, for operator-owned relays)', () => {
  async function mintSegToken(upstream: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return createToken(env.SECRET_KEY, { u: upstream, iat: now, exp: now + 300, k: 's' });
  }

  it('sends no X-Forwarded-For/X-Real-IP by default', async () => {
    const token = await mintSegToken('https://fwdip.example.com/seg1.ts');
    fetchMock
      .get('https://fwdip.example.com')
      .intercept({
        path: '/seg1.ts',
        headers: (h) => h['x-forwarded-for'] === undefined && h['x-real-ip'] === undefined,
      })
      .reply(200, 'TSDATA', { headers: { 'Content-Type': 'video/mp2t' } });
    const res = await handleSegment(
      new Request(`${BASE}/seg/${token}.ts`, { headers: { 'CF-Connecting-IP': '203.0.113.9' } }),
      env,
      'req-fwd-default',
      `${token}.ts`,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('TSDATA');
  });

  it('FORWARD_CLIENT_IP=true attaches the viewer IP on upstream fetches', async () => {
    const token = await mintSegToken('https://fwdip.example.com/seg2.ts');
    fetchMock
      .get('https://fwdip.example.com')
      .intercept({
        path: '/seg2.ts',
        headers: (h) => h['x-forwarded-for'] === '203.0.113.9' && h['x-real-ip'] === '203.0.113.9',
      })
      .reply(200, 'TSDATA', { headers: { 'Content-Type': 'video/mp2t' } });
    const res = await handleSegment(
      new Request(`${BASE}/seg/${token}.ts`, { headers: { 'CF-Connecting-IP': '203.0.113.9' } }),
      { ...env, FORWARD_CLIENT_IP: 'true' },
      'req-fwd-on',
      `${token}.ts`,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('TSDATA');
  });

  it('FORWARD_CLIENT_IP=true also applies to manifest fetches', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(env.SECRET_KEY, { u: 'https://fwdip.example.com/live.m3u8', iat: now, exp: now + 300, k: 'm' });
    fetchMock
      .get('https://fwdip.example.com')
      .intercept({
        path: '/live.m3u8',
        headers: (h) => h['x-forwarded-for'] === '203.0.113.9',
      })
      .reply(200, HLS_OK, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });
    const res = await handleHlsManifest(
      new Request(`${BASE}/hls/${token}.m3u8`, { headers: { 'CF-Connecting-IP': '203.0.113.9' } }),
      { ...env, FORWARD_CLIENT_IP: 'true' },
      'req-fwd-manifest',
      token,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBeNull();
  });

  it('never forwards a spoofed X-Forwarded-For supplied by the client itself', async () => {
    const token = await mintSegToken('https://fwdip.example.com/seg3.ts');
    // Only the CF-observed IP may be emitted; a client-supplied XFF is dropped.
    fetchMock
      .get('https://fwdip.example.com')
      .intercept({
        path: '/seg3.ts',
        headers: (h) => h['x-forwarded-for'] === '203.0.113.9',
      })
      .reply(200, 'TSDATA', { headers: { 'Content-Type': 'video/mp2t' } });
    const res = await handleSegment(
      new Request(`${BASE}/seg/${token}.ts`, {
        headers: { 'CF-Connecting-IP': '203.0.113.9', 'X-Forwarded-For': '1.2.3.4' },
      }),
      { ...env, FORWARD_CLIENT_IP: 'true' },
      'req-fwd-spoof',
      `${token}.ts`,
    );
    expect(res.status).toBe(200);
  });

  it('does not forward conditional headers upstream (304 empty bodies would poison the cache)', async () => {
    const token = await mintSegToken('https://fwdip.example.com/seg4.ts');
    fetchMock
      .get('https://fwdip.example.com')
      .intercept({
        path: '/seg4.ts',
        headers: (h) => h['if-none-match'] === undefined && h['if-modified-since'] === undefined,
      })
      .reply(200, 'TSDATA', { headers: { 'Content-Type': 'video/mp2t' } });
    const res = await handleSegment(
      new Request(`${BASE}/seg/${token}.ts`, {
        headers: { 'If-None-Match': '"abc"', 'If-Modified-Since': 'Wed, 01 Jan 2020 00:00:00 GMT' },
      }),
      env,
      'req-no-conditional',
      `${token}.ts`,
    );
    expect(res.status).toBe(200);
  });
});

