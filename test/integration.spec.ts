import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { SELF, env, fetchMock } from 'cloudflare:test';
import { createToken } from '../src/token';
import { syncPlaylist } from '../src/playlist/sync';
import { handleHlsManifest } from '../src/proxy/handlers';
import { hashPassword, randomHex } from '../src/utils/crypto';

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

describe('routing basics', () => {
  it('GET / returns the landing page', async () => {
    const res = await SELF.fetch(`${BASE}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('CHRTV');
    expect(html).toContain('Cloud IPTV Gateway');
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
});

describe('/tv.m3u playlist', () => {
  it('serves a tokenized playlist with zero configuration', async () => {
    await seedChannels();
    const res = await SELF.fetch(`${BASE}/tv.m3u`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('mpegurl');
    const body = await res.text();
    expect(body.startsWith('#EXTM3U')).toBe(true);
    expect(body).toContain('VTV1');
    expect(body).toContain(`${BASE}/hls/`);
    expect(body).not.toContain('up.example.com'); // upstream never exposed
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

  it('rejects an invalid access key even in public mode', async () => {
    const res = await SELF.fetch(`${BASE}/tv.m3u?key=chr_definitely_wrong_key`);
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('KEY_INVALID');
  });
});

describe('access keys + MAC devices', () => {
  async function createKey(maxDevices = 2): Promise<string> {
    const res = await SELF.fetch(`${BASE}/api/admin/keys`, {
      method: 'POST',
      headers: { ...ADMIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: 'test', max_devices: maxDevices }),
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

  it('revoked keys are rejected', async () => {
    const key = await createKey();
    const list = await SELF.fetch(`${BASE}/api/admin/keys`, { headers: ADMIN });
    const keys = (await list.json()) as Array<{ id: number; key_prefix: string }>;
    const row = keys.find((k) => key.startsWith(k.key_prefix))!;
    const del = await SELF.fetch(`${BASE}/api/admin/keys/${row.id}`, { method: 'DELETE', headers: ADMIN });
    expect(del.status).toBe(200);
    const res = await SELF.fetch(`${BASE}/tv.m3u?key=${key}`);
    expect(res.status).toBe(403);
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
    expect(list[0]!.direct_source).toBe(''); // upstream never exposed
    expect(list.some((s) => s.name === 'VTV1')).toBe(true);
  });

  it('get.php requires valid credentials and returns the tokenized M3U', async () => {
    await seedChannels();
    await seedUser('bob', 'password123');
    const bad = await SELF.fetch(`${BASE}/get.php?username=bob&password=wrong`);
    expect(bad.status).toBe(401);
    const ok = await SELF.fetch(`${BASE}/get.php?username=bob&password=password123&type=m3u_plus`);
    expect(ok.status).toBe(200);
    const text = await ok.text();
    expect(text).toContain('#EXTM3U');
    expect(text).not.toContain('up.example.com');
  });

  it('get.php works for a fresh Xtream client in public mode (no pre-created user)', async () => {
    await seedChannels();
    const res = await SELF.fetch(`${BASE}/get.php?username=anyuser&password=anypass&type=m3u_plus&output=m3u8`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('#EXTM3U');
    expect(text).toContain('VTV1');
    expect(text).not.toContain('up.example.com');
  });

  it('player_api handshake succeeds for a guest in public mode', async () => {
    const res = await SELF.fetch(`${BASE}/player_api.php?username=guest1&password=guest1`);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { user_info: { auth: number } }).user_info.auth).toBe(1);
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

  it('upstream 404 returns a valid CHRTV error manifest (not HTML)', async () => {
    fetchMock.get('https://dead1.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const token = await mintToken('https://dead1.example.com/gone.m3u8', { channel: 'deadchannel0001x' });
    const res = await SELF.fetch(`${BASE}/hls/${token}.m3u8`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain('#EXTM3U');
    expect(body).toContain('#EXT-X-ENDLIST');
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

  it('falls back to the empty error manifest when FALLBACK_M3U_URL is unset', async () => {
    fetchMock.get('https://deadnb.example.com').intercept({ path: '/gone.m3u8' }).reply(404, 'not found');
    const token = await mintToken('https://deadnb.example.com/gone.m3u8', { channel: 'nbchannel000001x' });
    const res = await handleHlsManifest(new Request(`${BASE}/hls/${token}.m3u8`), env, 'req-nofallback-123', token);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-CHRTV-Fallback')).toBe('1');
    const body = await res.text();
    expect(body).toContain('#EXT-X-ENDLIST');
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

  it('/live/{user}/{pass}/{id}.m3u8 serves the rewritten channel manifest', async () => {
    await seedChannels();
    await seedUser('bob', 'password123');
    const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\ns1.ts\n#EXT-X-ENDLIST\n';
    fetchMock.get('https://up.example.com').intercept({ path: '/live/vtv1/index.m3u8' }).reply(200, manifest);
    const res = await SELF.fetch(`${BASE}/live/bob/password123/100001.m3u8`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('/seg/');
    expect(body).not.toContain('up.example.com');

    const bad = await SELF.fetch(`${BASE}/live/bob/wrongpass/100001.m3u8`);
    expect(bad.status).toBe(401);
    const missing = await SELF.fetch(`${BASE}/live/bob/password123/999999.m3u8`);
    expect(missing.status).toBe(404);
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
  it('serves minimal valid XMLTV when no source is configured', async () => {
    await seedChannels();
    const res = await SELF.fetch(`${BASE}/xmltv.php`);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('xml');
    const body = await res.text();
    expect(body).toContain('<?xml');
    expect(body).toContain('<tv');
    expect(body).toContain('</tv>');
  });
});
