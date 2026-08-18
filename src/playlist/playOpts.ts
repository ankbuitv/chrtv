/**
 * Per-channel playback hints parsed from #EXTVLCOPT / #KODIPROP lines that
 * sit between #EXTINF and the URL. IPTV apps (Kodi, TiviMate, VLC) use these
 * to pick DASH vs HLS, attach a Referer/UA, and unlock ClearKey streams.
 *
 * CHRTV stores the compact JSON on the channel row and:
 *  - injects UA / Referer / extra headers on every upstream fetch (so the
 *    origin never has to be leaked to the player);
 *  - emits KODIPROP ClearKey + manifest_type back out on /tv.m3u so Kodi
 *    / TiviMate can still decrypt DASH;
 *  - hands ClearKey to the /xem web player (dash.js EME).
 */

export type ManifestKind = 'hls' | 'mpd' | 'auto';

export interface ClearKey {
  kid: string;
  key: string;
}

export interface PlayOpts {
  kind: ManifestKind;
  ua?: string;
  referrer?: string;
  headers?: Record<string, string>;
  clearkey?: ClearKey;
}

const HEX32 = /^[0-9a-f]{32}$/i;
const MAX_UA = 256;
const MAX_REF = 512;
const MAX_HEADER_VALUE = 256;
const MAX_HEADERS = 6;

/** Hop-by-hop / identity headers we never honour from a playlist. */
const BLOCKED_HEADERS = new Set([
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'cookie',
  'set-cookie',
  'authorization',
  'content-length',
  'content-type',
  'accept-encoding',
  'if-none-match',
  'if-modified-since',
]);

export function emptyPlayOpts(): PlayOpts {
  return { kind: 'auto' };
}

export function isSafeHeaderName(name: string): boolean {
  return /^[a-z0-9-]{1,40}$/i.test(name) && !BLOCKED_HEADERS.has(name.toLowerCase());
}

function clip(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}

function parseClearKey(raw: string): ClearKey | undefined {
  // Kodi ClearKey is `kid:key` (32 hex chars each). A few playlists use
  // `{kid:key}` or `kid=…&key=…`; accept the common variants.
  const cleaned = raw.trim().replace(/^\{|\}$/g, '');
  const pair = cleaned.match(/^([0-9a-f]{32})\s*[:|=]\s*([0-9a-f]{32})$/i);
  if (pair && HEX32.test(pair[1]!) && HEX32.test(pair[2]!)) {
    return { kid: pair[1]!.toLowerCase(), key: pair[2]!.toLowerCase() };
  }
  return undefined;
}

function setHeader(opts: PlayOpts, name: string, value: string): void {
  if (!isSafeHeaderName(name) || !value) return;
  opts.headers ??= {};
  if (Object.keys(opts.headers).length >= MAX_HEADERS && !(name in opts.headers)) return;
  opts.headers[name] = clip(value.trim(), MAX_HEADER_VALUE);
}

/**
 * Parse a single directive line (`#EXTVLCOPT:…` / `#KODIPROP:…`).
 * Unknown keys are ignored.
 */
export function applyDirective(opts: PlayOpts, line: string): void {
  const raw = line.trim();
  if (raw.startsWith('#EXTVLCOPT:')) {
    const body = raw.slice('#EXTVLCOPT:'.length);
    const eq = body.indexOf('=');
    if (eq <= 0) return;
    const key = body.slice(0, eq).trim().toLowerCase();
    const value = body.slice(eq + 1).trim();
    if (!value) return;
    if (key === 'http-user-agent' || key === 'http-useragent') opts.ua = clip(value, MAX_UA);
    else if (key === 'http-referrer' || key === 'http-referer') opts.referrer = clip(value, MAX_REF);
    return;
  }
  if (!raw.startsWith('#KODIPROP:')) return;
  const body = raw.slice('#KODIPROP:'.length);
  const eq = body.indexOf('=');
  if (eq <= 0) return;
  const key = body.slice(0, eq).trim().toLowerCase();
  const value = body.slice(eq + 1).trim();
  if (!value) return;

  if (key === 'inputstream.adaptive.manifest_type' || key === 'inputstream.adaptive.manifesttype') {
    const v = value.toLowerCase();
    if (v === 'mpd' || v === 'dash') opts.kind = 'mpd';
    else if (v === 'hls' || v === 'm3u8') opts.kind = 'hls';
    return;
  }
  if (key === 'inputstream.adaptive.license_key' || key === 'inputstream.adaptive.licensekey') {
    const ck = parseClearKey(value);
    if (ck) opts.clearkey = ck;
    return;
  }
  if (key === 'inputstream.adaptive.stream_headers' || key === 'inputstream.adaptive.streamheaders') {
    // `Name=value&Name2=value2` (Kodi) — also accept `Name: value`.
    for (const part of value.split(/&/)) {
      const m = part.match(/^([^:=]+)[:=](.*)$/);
      if (!m) continue;
      const header = m[1]!.trim();
      const headerVal = m[2]!.trim();
      if (header.toLowerCase() === 'user-agent') opts.ua = clip(headerVal, MAX_UA);
      else if (header.toLowerCase() === 'referer' || header.toLowerCase() === 'referrer') opts.referrer = clip(headerVal, MAX_REF);
      else setHeader(opts, header, headerVal);
    }
  }
}

export function serializePlayOpts(opts: PlayOpts): string {
  if (opts.kind === 'auto' && !opts.ua && !opts.referrer && !opts.headers && !opts.clearkey) return '';
  return JSON.stringify(opts);
}

export function parsePlayOpts(raw: string | null | undefined): PlayOpts {
  if (!raw) return emptyPlayOpts();
  try {
    const parsed = JSON.parse(raw) as Partial<PlayOpts>;
    if (!parsed || typeof parsed !== 'object') return emptyPlayOpts();
    const opts: PlayOpts = { kind: parsed.kind === 'mpd' || parsed.kind === 'hls' ? parsed.kind : 'auto' };
    if (typeof parsed.ua === 'string' && parsed.ua) opts.ua = clip(parsed.ua, MAX_UA);
    if (typeof parsed.referrer === 'string' && parsed.referrer) opts.referrer = clip(parsed.referrer, MAX_REF);
    if (parsed.clearkey && HEX32.test(parsed.clearkey.kid ?? '') && HEX32.test(parsed.clearkey.key ?? '')) {
      opts.clearkey = { kid: parsed.clearkey.kid.toLowerCase(), key: parsed.clearkey.key.toLowerCase() };
    }
    if (parsed.headers && typeof parsed.headers === 'object') {
      for (const [k, v] of Object.entries(parsed.headers)) {
        if (typeof v === 'string') setHeader(opts, k, v);
      }
    }
    return opts;
  } catch {
    return emptyPlayOpts();
  }
}

/** Guess the manifest kind from a URL when the playlist didn't declare one. */
export function kindFromUrl(url: string): ManifestKind {
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    const q = u.search.toLowerCase();
    if (path.endsWith('.mpd') || q.includes('.mpd') || /(?:^|[?&])(?:ext|type|format)=(?:\.?)?(mpd|dash)\b/.test(q)) {
      return 'mpd';
    }
    if (path.endsWith('.m3u8') || path.endsWith('.m3u') || q.includes('.m3u8') || /(?:^|[?&])(?:ext|type|format)=(?:\.?)?(m3u8?|hls)\b/.test(q)) {
      return 'hls';
    }
  } catch {
    /* ignore */
  }
  return 'auto';
}

export function resolvedKind(opts: PlayOpts, url: string): 'hls' | 'mpd' {
  if (opts.kind === 'mpd' || opts.kind === 'hls') return opts.kind;
  return kindFromUrl(url) === 'mpd' ? 'mpd' : 'hls';
}

/**
 * Compact extra-header payload carried inside the encrypted stream token
 * (`Header:value` per line). Bounded so tokens stay well under the 4 kB cap.
 */
export function serializeTokenHeaders(headers: Record<string, string> | undefined): string | undefined {
  if (!headers) return undefined;
  const lines = Object.entries(headers)
    .filter(([k, v]) => isSafeHeaderName(k) && v)
    .slice(0, MAX_HEADERS)
    .map(([k, v]) => `${k}:${clip(v, MAX_HEADER_VALUE)}`);
  return lines.length ? lines.join('\n') : undefined;
}

/** Compact token fields derived from stored play_opts + the channel URL. */
export function tokenHintsFromPlayOpts(
  rawOpts: string | null | undefined,
  url: string,
): { rf?: string; ua?: string; xh?: string } {
  const opts = parsePlayOpts(rawOpts);
  const hints: { rf?: string; ua?: string; xh?: string } = {};
  if (opts.referrer) hints.rf = opts.referrer;
  else {
    try {
      hints.rf = `${new URL(url).origin}/`;
    } catch {
      /* ignore */
    }
  }
  if (opts.ua) hints.ua = opts.ua;
  const xh = serializeTokenHeaders(opts.headers);
  if (xh) hints.xh = xh;
  return hints;
}

export function parseTokenHeaders(raw: string | undefined): Array<[string, string]> {
  if (!raw) return [];
  const out: Array<[string, string]> = [];
  for (const line of raw.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!isSafeHeaderName(name) || !value) continue;
    out.push([name, clip(value, MAX_HEADER_VALUE)]);
    if (out.length >= MAX_HEADERS) break;
  }
  return out;
}
