import { describe, it, expect } from 'vitest';
import { normalizeMac } from '../src/utils/mac';
import { isSafeUpstreamUrl } from '../src/utils/urlsafe';
import { isFetchablePort } from '../src/utils/ports';
import { createToken, parseTokenBindingPolicy, requestTokenBinding, verifyToken } from '../src/token';
import { parsePlaylist, PlaylistError } from '../src/playlist/parser';
import { rewriteManifest, looksLikeHls, HlsError } from '../src/hls/rewrite';
import { buildErrorManifest } from '../src/hls/errorManifest';
import { hashPassword, hashAccessKey, timingSafeEqual, randomHex } from '../src/utils/crypto';
import { isHoneypotPath, shouldBanHoneypotRequest } from '../src/security/honeypot';
import { parsePrivateLogin } from '../src/auth/privateLogin';

const SECRET = 'unit-test-secret-0123456789abcdef';

describe('security route parsing', () => {
  it('recognizes conservative vulnerability-scan traps, including encoded/case variants', () => {
    for (const path of ['/.env', '/.env.production', '/.git/config', '/WP-LOGIN.php', '/phpMyAdmin/', '/%2eenv']) {
      expect(isHoneypotPath(path)).toBe(true);
    }
  });

  it('does not trap legitimate CHRTV, generic admin, or IPTV portal paths', () => {
    for (const path of ['/', '/tv.m3u', '/api/admin/status', '/admin', '/portal.php', '/stalker_portal/server/load.php']) {
      expect(isHoneypotPath(path)).toBe(false);
    }
  });

  it('suppresses only browser-declared cross-site honeypot side effects', () => {
    expect(shouldBanHoneypotRequest(new Request('https://chrtv.example/.env'))).toBe(true);
    expect(
      shouldBanHoneypotRequest(
        new Request('https://chrtv.example/.env', { headers: { 'Sec-Fetch-Site': 'same-origin' } }),
      ),
    ).toBe(true);
    expect(
      shouldBanHoneypotRequest(
        new Request('https://chrtv.example/.env', { headers: { 'Sec-Fetch-Site': 'cross-site' } }),
      ),
    ).toBe(false);
  });

  it('parses only the compact /lg/{username}?{password}.m3u form', () => {
    expect(parsePrivateLogin(new URL('https://chrtv.example/lg/ken?strong%20password.m3u'))).toEqual({
      username: 'ken',
      password: 'strong password',
    });
    expect(parsePrivateLogin(new URL('https://chrtv.example/lg/ken?password=wrong.m3u'))).toBeNull();
    expect(parsePrivateLogin(new URL('https://chrtv.example/lg/ken/password.m3u'))).toBeNull();
    expect(parsePrivateLogin(new URL('https://chrtv.example/lg/ken%2Fother?password.m3u'))).toBeNull();
    expect(parsePrivateLogin(new URL(`https://chrtv.example/lg/ken?${'p'.repeat(257)}.m3u`))).toBeNull();
  });
});

describe('MAC normalization', () => {
  it('normalizes colon format', () => {
    expect(normalizeMac('aa:bb:cc:dd:ee:ff')).toBe('AA:BB:CC:DD:EE:FF');
  });
  it('normalizes dash format', () => {
    expect(normalizeMac('AA-BB-CC-DD-EE-FF')).toBe('AA:BB:CC:DD:EE:FF');
  });
  it('normalizes bare hex and dots', () => {
    expect(normalizeMac('aabbccddeeff')).toBe('AA:BB:CC:DD:EE:FF');
    expect(normalizeMac('aabb.ccdd.eeff')).toBe('AA:BB:CC:DD:EE:FF');
  });
  it('rejects invalid MACs', () => {
    expect(normalizeMac('')).toBeNull();
    expect(normalizeMac('zz:bb:cc:dd:ee:ff')).toBeNull();
    expect(normalizeMac('aa:bb:cc:dd:ee')).toBeNull();
    expect(normalizeMac(null)).toBeNull();
  });
});

describe('configurable token identity binding', () => {
  const req = new Request('https://chrtv.example.com/tv.m3u', {
    headers: { 'CF-Connecting-IP': '203.0.113.8', 'X-Forwarded-For': '198.51.100.99' },
  });

  it('enables all claims by default and ignores spoofable forwarded IPs', () => {
    expect(requestTokenBinding(req, { rawMac: 'aa-bb-cc-dd-ee-ff', userId: 7, accessKeyId: 9 })).toEqual({
      ip: '203.0.113.8',
      mac: 'AA:BB:CC:DD:EE:FF',
      uid: 7,
      aid: 9,
    });
  });

  it('supports selected claims or an explicit none policy', () => {
    expect(requestTokenBinding(req, { rawMac: 'aa:bb:cc:dd:ee:ff', userId: 7, accessKeyId: 9 }, 'mac,user')).toEqual({
      mac: 'AA:BB:CC:DD:EE:FF',
      uid: 7,
    });
    expect(requestTokenBinding(req, { rawMac: 'aa:bb:cc:dd:ee:ff', userId: 7 }, 'none')).toEqual({});
    expect(requestTokenBinding(req, { userId: 7, sessionId: 11 }, 'none')).toEqual({ uid: 7, sid: 11 });
  });

  it('fails safe to the all-claims policy on configuration typos', () => {
    expect(parseTokenBindingPolicy('ip,uesr')).toEqual({ ip: true, mac: true, user: true, key: true });
  });
});

describe('SSRF guard', () => {
  it('allows public http/https', () => {
    expect(isSafeUpstreamUrl('https://cdn.example.com/live/index.m3u8')).toBe(true);
    expect(isSafeUpstreamUrl('http://stream.example.com:8080/x.ts?a=1')).toBe(true);
  });
  it('blocks non-http protocols', () => {
    for (const u of ['file:///etc/passwd', 'ftp://x.com/a', 'data:text/html,x', 'javascript:alert(1)', 'blob:https://x']) {
      expect(isSafeUpstreamUrl(u)).toBe(false);
    }
  });
  it('blocks localhost and private/link-local IPs', () => {
    for (const u of [
      'http://localhost/x',
      'http://127.0.0.1/x',
      'http://0.0.0.0/x',
      'http://10.1.2.3/x',
      'http://172.16.0.1/x',
      'http://192.168.1.1/x',
      'http://169.254.169.254/latest/meta-data',
      'http://100.64.0.1/x',
      'http://[::1]/x',
      'http://[fe80::1]/x',
      'http://[fd00::1]/x',
      'http://metadata.google.internal/x',
      'http://intranet/x',
      'http://2130706433/x',
      'http://0x7f000001/x',
    ]) {
      expect(isSafeUpstreamUrl(u)).toBe(false);
    }
  });
  it('blocks credentials in URL and malformed URLs', () => {
    expect(isSafeUpstreamUrl('https://user:pass@example.com/x')).toBe(false);
    expect(isSafeUpstreamUrl('not a url')).toBe(false);
  });
});

describe('stream tokens', () => {
  it('round-trips a payload', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(SECRET, { u: 'https://cdn.example.com/a.m3u8', iat: now, exp: now + 60, k: 'm', c: 'abc' });
    const res = await verifyToken(SECRET, token);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.payload.u).toBe('https://cdn.example.com/a.m3u8');
      expect(res.payload.c).toBe('abc');
    }
  });
  it('rejects expired tokens', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(SECRET, { u: 'https://cdn.example.com/a.ts', iat: now - 120, exp: now - 60 });
    const res = await verifyToken(SECRET, token);
    expect(res).toEqual({ ok: false, code: 'TOKEN_EXPIRED' });
  });
  it('rejects tampered tokens', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(SECRET, { u: 'https://cdn.example.com/a.ts', iat: now, exp: now + 60 });
    const tampered = token.slice(0, -4) + (token.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    const res = await verifyToken(SECRET, tampered);
    expect(res.ok).toBe(false);
  });
  it('rejects tokens minted with a different secret', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken('other-secret-xxxxxxxxxxxxxxxxxx', { u: 'https://cdn.example.com/a.ts', iat: now, exp: now + 60 });
    const res = await verifyToken(SECRET, token);
    expect(res).toEqual({ ok: false, code: 'TOKEN_INVALID' });
  });
  it('rejects garbage and oversized tokens', async () => {
    expect((await verifyToken(SECRET, '')).ok).toBe(false);
    expect((await verifyToken(SECRET, '!!!not-base64!!!')).ok).toBe(false);
    expect((await verifyToken(SECRET, 'A'.repeat(5000))).ok).toBe(false);
  });
  it('rejects tokens whose embedded URL is unsafe', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(SECRET, { u: 'http://169.254.169.254/meta', iat: now, exp: now + 60 });
    const res = await verifyToken(SECRET, token);
    expect(res).toEqual({ ok: false, code: 'UNSAFE_URL' });
  });
  it('rejects session claims without a user owner', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken(SECRET, {
      u: 'https://cdn.example.com/a.m3u8',
      iat: now,
      exp: now + 60,
      k: 'm',
      sid: 11,
    });
    expect(await verifyToken(SECRET, token)).toEqual({ ok: false, code: 'TOKEN_INVALID' });
  });
});

describe('credential hashing', () => {
  it('password hash is deterministic per salt and secret-keyed', async () => {
    const h1 = await hashPassword(SECRET, 'salt1', 'pw');
    const h2 = await hashPassword(SECRET, 'salt1', 'pw');
    const h3 = await hashPassword(SECRET, 'salt2', 'pw');
    const h4 = await hashPassword('other-secret', 'salt1', 'pw');
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1).not.toBe(h4);
  });
  it('access key hash never equals the raw key', async () => {
    const key = `chr_${randomHex(24)}`;
    const hash = await hashAccessKey(SECRET, key);
    expect(hash).not.toContain(key);
    expect(hash).toHaveLength(64);
  });
  it('timingSafeEqual', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
  });
});

describe('playlist parser', () => {
  const sample = `#EXTM3U
#EXTINF:-1 tvg-id="vtv1" tvg-logo="https://logo/x.png" group-title="News",VTV1
https://cdn.example.com/vtv1.m3u8
#EXTINF:-1 tvg-id="vtv2" group-title="News",VTV2
https://cdn.example.com/vtv2.m3u8
#EXTINF:-1,No Group
https://cdn.example.com/nogroup.m3u8
`;

  it('parses channels, categories, attributes', async () => {
    const res = await parsePlaylist(sample);
    expect(res.channels).toHaveLength(3);
    expect(res.categories).toEqual(['News', 'Uncategorized']);
    expect(res.channels[0]).toMatchObject({ name: 'VTV1', tvgId: 'vtv1', tvgLogo: 'https://logo/x.png', group: 'News' });
  });
  it('produces stable channel ids across parses', async () => {
    const a = await parsePlaylist(sample);
    const b = await parsePlaylist(sample + '\n');
    expect(a.channels.map((c) => c.id)).toEqual(b.channels.map((c) => c.id));
  });
  it('collapses duplicates', async () => {
    const dup = sample + '#EXTINF:-1 tvg-id="vtv1" group-title="News",VTV1\nhttps://cdn.example.com/vtv1.m3u8\n';
    const res = await parsePlaylist(dup);
    expect(res.channels).toHaveLength(3);
    expect(res.skipped).toBe(1);
  });
  it('accepts channels on non-standard ports', async () => {
    const customPort = `#EXTM3U\n#EXTINF:-1 tvg-id="custom",Custom Channel\nhttp://chrtv.duckdns.org:18483/stream/cg_hbofam/index.m3u8\n`;
    const res = await parsePlaylist(customPort);
    expect(res.channels).toHaveLength(1);
    expect(res.channels[0]!.url).toBe('http://chrtv.duckdns.org:18483/stream/cg_hbofam/index.m3u8');
    expect(res.skipped).toBe(0);
  });

  it('skips unsafe URLs', async () => {
    const bad = '#EXTM3U\n#EXTINF:-1,Evil\nhttp://127.0.0.1/x.m3u8\n#EXTINF:-1,Good\nhttps://ok.example.com/x.m3u8\n';
    const res = await parsePlaylist(bad);
    expect(res.channels).toHaveLength(1);
    expect(res.skipped).toBe(1);
  });
  it('rejects invalid playlists', async () => {
    await expect(parsePlaylist('not an m3u')).rejects.toThrow(PlaylistError);
    await expect(parsePlaylist('#EXTM3U\n')).rejects.toThrow(PlaylistError);
  });
  it('handles CRLF', async () => {
    const res = await parsePlaylist(sample.replace(/\n/g, '\r\n'));
    expect(res.channels).toHaveLength(3);
  });
});

describe('HLS rewriting', () => {
  const opts = {
    secret: SECRET,
    baseUrl: 'https://origin.example.com/live/abc/index.m3u8?auth=1',
    publicOrigin: 'https://chrtv.example.com',
  };

  async function verifyProxied(url: string): Promise<string> {
    expect(url.startsWith('https://chrtv.example.com/')).toBe(true);
    const m = url.match(/\/(hls|seg)\/([^.?]+)/);
    expect(m).toBeTruthy();
    const res = await verifyToken(SECRET, m![2]!);
    expect(res.ok).toBe(true);
    return res.ok ? res.payload.u : '';
  }

  it('rewrites relative segment URIs against the final (redirected) URL', async () => {
    const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nsegment001.ts\n#EXT-X-ENDLIST\n';
    const out = await rewriteManifest(manifest, opts);
    const segLine = out.split('\n').find((l) => l.includes('/seg/'))!;
    expect(await verifyProxied(segLine)).toBe('https://origin.example.com/live/abc/segment001.ts');
  });
  it('handles absolute, protocol-relative and query-string URIs', async () => {
    const manifest = [
      '#EXTM3U',
      '#EXTINF:6.0,',
      'https://other.example.com/seg1.ts',
      '#EXTINF:6.0,',
      '//proto.example.com/seg2.ts',
      '#EXTINF:6.0,',
      'seg3.ts?token=abc&x=1',
      '#EXT-X-ENDLIST',
    ].join('\n');
    const out = await rewriteManifest(manifest, opts);
    const segs = out.split('\n').filter((l) => l.includes('/seg/'));
    expect(await verifyProxied(segs[0]!)).toBe('https://other.example.com/seg1.ts');
    expect(await verifyProxied(segs[1]!)).toBe('https://proto.example.com/seg2.ts');
    expect(await verifyProxied(segs[2]!)).toBe('https://origin.example.com/live/abc/seg3.ts?token=abc&x=1');
  });
  it('rewrites child manifests in master playlists as manifest tokens', async () => {
    const manifest = '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2000000\nhd/index.m3u8\n';
    const out = await rewriteManifest(manifest, opts);
    const line = out.split('\n').find((l) => l.includes('/hls/'))!;
    expect(line).toContain('.m3u8');
    expect(await verifyProxied(line)).toBe('https://origin.example.com/live/abc/hd/index.m3u8');
  });
  it('rewrites EXT-X-KEY URIs', async () => {
    const manifest = '#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="keys/k1.key",IV=0x1234\n#EXTINF:6.0,\ns.ts\n#EXT-X-ENDLIST\n';
    const out = await rewriteManifest(manifest, opts);
    const keyLine = out.split('\n').find((l) => l.startsWith('#EXT-X-KEY'))!;
    expect(keyLine).toContain('IV=0x1234');
    const uri = keyLine.match(/URI="([^"]+)"/)![1]!;
    expect(await verifyProxied(uri)).toBe('https://origin.example.com/live/abc/keys/k1.key');
  });
  it('rewrites media, key, subtitle, rendition, image, and low-latency URI attributes', async () => {
    const manifest = [
      '#EXTM3U',
      '#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="aud",URI="audio/index.m3u8"',
      '#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=100000,URI="iframe.m3u8"',
      '#EXT-X-RENDITION-REPORT:URI="low/index.m3u8",LAST-MSN=12',
      '#EXT-X-IMAGE-STREAM-INF:BANDWIDTH=1000,URI="images/index.m3u8"',
      '#EXT-X-MAP:URI="init.mp4"',
      '#EXT-X-PART:DURATION=1.0,URI="part1.m4s"',
      '#EXT-X-PRELOAD-HINT:TYPE=PART,URI="part2.m4s"',
      '#EXTINF:6.0,',
      'seg.m4s',
      '#EXT-X-ENDLIST',
    ].join('\n');
    const out = await rewriteManifest(manifest, opts);
    const media = out.split('\n').find((l) => l.startsWith('#EXT-X-MEDIA'))!;
    expect(media).toContain('/hls/'); // playlists proxied as manifests
    const map = out.split('\n').find((l) => l.startsWith('#EXT-X-MAP'))!;
    expect(await verifyProxied(map.match(/URI="([^"]+)"/)![1]!)).toBe('https://origin.example.com/live/abc/init.mp4');
    const part = out.split('\n').find((l) => l.startsWith('#EXT-X-PART'))!;
    expect(part).toContain('/seg/');
    const hint = out.split('\n').find((l) => l.startsWith('#EXT-X-PRELOAD-HINT'))!;
    expect(hint).toContain('/seg/');
    const iframe = out.split('\n').find((l) => l.startsWith('#EXT-X-I-FRAME-STREAM-INF'))!;
    expect(iframe).toContain('/hls/');
    const rendition = out.split('\n').find((l) => l.startsWith('#EXT-X-RENDITION-REPORT'))!;
    expect(rendition).toContain('/hls/');
    const images = out.split('\n').find((l) => l.startsWith('#EXT-X-IMAGE-STREAM-INF'))!;
    expect(images).toContain('/hls/');
  });
  it('fails closed instead of leaking unsafe, malformed, or recursively untokenized descendant URIs', async () => {
    const unsafe = '#EXTM3U\n#EXTINF:6.0,\nhttp://169.254.169.254/meta.ts\n#EXT-X-ENDLIST\n';
    await expect(rewriteManifest(unsafe, opts)).rejects.toThrow('unsafe manifest URI');
    const malformed = '#EXTM3U\n#EXTINF:6.0,\nhttp://[invalid\n#EXT-X-ENDLIST\n';
    await expect(rewriteManifest(malformed, opts)).rejects.toThrow('invalid manifest URI');
    const malformedAttr = '#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=https://key.example.com/raw.key\n';
    await expect(rewriteManifest(malformedAttr, opts)).rejects.toThrow('invalid manifest URI attribute');
    const steering = '#EXTM3U\n#EXT-X-CONTENT-STEERING:SERVER-URI="https://steering.example.com/config.json"\n';
    await expect(rewriteManifest(steering, opts)).rejects.toThrow('unsupported manifest URI attribute');
  });
  it('rejects non-HLS and oversized manifests', async () => {
    await expect(rewriteManifest('<html>err</html>', opts)).rejects.toThrow(HlsError);
    await expect(rewriteManifest('#EXTM3U\n' + 'x'.repeat(3 * 1024 * 1024), opts)).rejects.toThrow(HlsError);
    expect(looksLikeHls('#EXTM3U\n')).toBe(true);
    expect(looksLikeHls('<html>')).toBe(false);
  });
});

describe('error manifest', () => {
  it('is valid ended HLS with no leaks', () => {
    const m = buildErrorManifest();
    expect(m.startsWith('#EXTM3U')).toBe(true);
    expect(m).toContain('#EXT-X-ENDLIST');
    expect(m).toContain('#EXT-X-TARGETDURATION');
    expect(m).not.toContain('http');
    expect(m).not.toContain('<');
  });
});

describe('Workers-fetchable ports', () => {
  it('allows default and Cloudflare-compatible ports', () => {
    expect(isFetchablePort('https://cdn.example.com/x.m3u8')).toBe(true);
    expect(isFetchablePort('http://cdn.example.com/x.m3u8')).toBe(true);
    expect(isFetchablePort('http://cdn.example.com:80/x')).toBe(true);
    expect(isFetchablePort('http://cdn.example.com:8080/x')).toBe(true);
    expect(isFetchablePort('https://cdn.example.com:8443/x')).toBe(true);
    expect(isFetchablePort('https://cdn.example.com:2053/x')).toBe(true);
  });
  it('rejects ports a Worker subrequest cannot open', () => {
    // These silently land on :80/:443 and stall the player.
    expect(isFetchablePort('http://chrtv.duckdns.org:30113/hls/index.m3u8')).toBe(false);
    expect(isFetchablePort('http://host.example.com:8989/x')).toBe(false);
    expect(isFetchablePort('https://host.example.com:8080/x')).toBe(false); // http-only port
    expect(isFetchablePort('http://host.example.com:8443/x')).toBe(false); // https-only port
  });
  it('rejects malformed URLs', () => {
    expect(isFetchablePort('not a url')).toBe(false);
  });
});

describe('token stability (anti re-buffering)', () => {
  const opts = {
    secret: SECRET,
    baseUrl: 'https://origin.example.com/live/abc/index.m3u8',
    publicOrigin: 'https://chrtv.example.com',
  };
  const manifest = '#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nseg1.ts\n#EXTINF:6.0,\nseg2.ts\n';

  it('produces identical segment URLs across manifest refreshes', async () => {
    const now = 1_800_000_000;
    const a = await rewriteManifest(manifest, { ...opts, now });
    const b = await rewriteManifest(manifest, { ...opts, now: now + 5 }); // player refresh
    expect(b).toBe(a);
  });

  it('still gives different URLs to different segments', async () => {
    const out = await rewriteManifest(manifest, { ...opts, now: 1_800_000_000 });
    const segs = out.split('\n').filter((l) => l.includes('/seg/'));
    expect(segs).toHaveLength(2);
    expect(segs[0]).not.toBe(segs[1]);
  });

  it('never issues descendant capabilities beyond the parent capability expiry', async () => {
    const now = 1_800_000_000;
    const absoluteExpiry = now + 30;
    const source = '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nchild.m3u8\n#EXTINF:6.0,\nseg.ts\n';
    const out = await rewriteManifest(source, { ...opts, now, absoluteExpiry });
    const urls = out.split('\n').filter((line) => line.startsWith('https://chrtv.example.com/'));
    expect(urls).toHaveLength(2);
    for (const url of urls) {
      const token = url.match(/\/(?:hls|seg)\/([^.?]+)/)![1]!;
      const verdict = await verifyToken(SECRET, token, now);
      expect(verdict.ok).toBe(true);
      if (verdict.ok) expect(verdict.payload.exp).toBe(absoluteExpiry);
    }
  });

  it('rejects custom-port descendants before issuing unusable capabilities', async () => {
    const custom = '#EXTM3U\n#EXTINF:6.0,\nhttp://origin.example.com:30113/seg.ts\n#EXT-X-ENDLIST\n';
    await expect(rewriteManifest(custom, opts)).rejects.toThrow('unsupported manifest URI port');
  });
});

describe('web player paste-and-play availability', () => {
  it('follows PUBLIC_PLAYLIST unless ALLOW_URL_PLAY overrides it', async () => {
    const { urlPlayEnabled } = await import('../src/player');
    const envOf = (vars: Record<string, string>) => vars as unknown as import('../src/types').Env;
    expect(urlPlayEnabled(envOf({}))).toBe(true); // default: public playlist => enabled
    expect(urlPlayEnabled(envOf({ PUBLIC_PLAYLIST: 'true' }))).toBe(true);
    expect(urlPlayEnabled(envOf({ PUBLIC_PLAYLIST: 'false' }))).toBe(false); // locked down => off
    expect(urlPlayEnabled(envOf({ PUBLIC_PLAYLIST: 'false', ALLOW_URL_PLAY: 'true' }))).toBe(true); // explicit opt-in
    expect(urlPlayEnabled(envOf({ PUBLIC_PLAYLIST: 'true', ALLOW_URL_PLAY: 'false' }))).toBe(false); // explicit opt-out
    expect(urlPlayEnabled(envOf({ ALLOW_URL_PLAY: 'false' }))).toBe(false);
  });
});
