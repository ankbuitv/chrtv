import { type TokenBinding } from '../token';
import { mintProxyUrl, MintError, type MintOptions } from '../proxy/mint';

/**
 * HLS manifest rewriter.
 * Every URI (line URIs and attribute URI="..." in tags) is resolved against the
 * FINAL upstream URL (post-redirect) and replaced by a CHRTV token URL:
 *   child manifests -> /hls/{token}.m3u8  (or /mpd/ when the URI is DASH)
 *   media/keys/maps -> /seg/{token}[.ext]
 * Any resolved URL that cannot be safely proxied rejects the manifest rather
 * than leaking a direct URI. URLs on ports Cloudflare Workers cannot fetch are
 * rejected too: redirecting the player would expose the raw origin.
 *
 * PHP / relay "proxies" often return a tiny M3U that just points at another
 * .m3u8 (sometimes without a .m3u8 extension — `index.php?id=…&ext=.m3u8`).
 * Those wrappers are detected here so the handler can follow them, and so a
 * leftover wrapper is rewritten as a real master playlist instead of as a
 * media segment (which hls.js then tries to demux as MPEG-TS and fails).
 */

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

// Tags whose URI attribute points to another *playlist*.
const MANIFEST_URI_TAGS = [
  '#EXT-X-MEDIA',
  '#EXT-X-I-FRAME-STREAM-INF',
  '#EXT-X-RENDITION-REPORT',
  '#EXT-X-IMAGE-STREAM-INF',
];
// Tags whose URI attribute points to *media* (segments, keys, init sections, parts).
const MEDIA_URI_TAGS = ['#EXT-X-KEY', '#EXT-X-SESSION-KEY', '#EXT-X-MAP', '#EXT-X-PART', '#EXT-X-PRELOAD-HINT'];

const MEDIA_EXTS = new Set(['ts', 'm4s', 'm4v', 'mp4', 'aac', 'ac3', 'vtt', 'srt', 'key', 'jpg', 'jpeg', 'png', 'webp']);

export class HlsError extends Error {}

export function looksLikeHls(text: string): boolean {
  return text.trimStart().startsWith('#EXTM3U');
}

export function extOf(url: string): string {
  try {
    const path = new URL(url).pathname;
    const dot = path.lastIndexOf('.');
    if (dot === -1) return '';
    const ext = path.slice(dot + 1).toLowerCase();
    return /^[a-z0-9]{1,5}$/.test(ext) ? ext : '';
  } catch {
    return '';
  }
}

export function resolveUri(uri: string, baseUrl: string): string | null {
  try {
    const base = new URL(baseUrl);
    const resolved = new URL(uri, baseUrl);
    // Preserve base query params (e.g. ?token=...) for relative / same-origin
    // segment URLs that don't specify their own query — required for tokenized
    // upstream streams where the manifest URL carries the auth/session token.
    if (
      base.search &&
      !resolved.search &&
      resolved.origin === base.origin &&
      !uri.trim().includes('?') &&
      !uri.trim().includes('#')
    ) {
      resolved.search = base.search;
    }
    return resolved.toString();
  } catch {
    return null;
  }
}

/** True when the URL itself is (or is advertised as) a playlist, not media. */
export function looksLikePlaylistUrl(url: string): boolean {
  const e = extOf(url);
  if (e === 'm3u8' || e === 'm3u' || e === 'mpd') return true;
  try {
    const u = new URL(url);
    const q = u.search.toLowerCase();
    if (q.includes('.m3u8') || q.includes('.m3u') || q.includes('.mpd')) return true;
    if (/(?:^|[?&])(?:ext|type|format|output)=(?:\.?)?(m3u8?|mpd|hls|dash)\b/i.test(u.search)) return true;
  } catch {
    /* ignore */
  }
  return false;
}

export function isObviousMediaUrl(url: string): boolean {
  return MEDIA_EXTS.has(extOf(url));
}

function isManifestUrl(url: string): boolean {
  return looksLikePlaylistUrl(url);
}

/** Non-comment URI lines (segments / child playlists), resolved against baseUrl. */
export function listUriLines(text: string, baseUrl: string): string[] {
  const out: string[] = [];
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const abs = resolveUri(line, baseUrl);
    if (abs) out.push(abs);
  }
  return out;
}

/**
 * A "wrapper" is a tiny M3U that only points at another playlist — the classic
 * PHP-proxy / portal pattern. It is NOT a real media playlist (no
 * TARGETDURATION, no obvious .ts/.m4s segments) and not already a master
 * (no STREAM-INF).
 *
 *  - one non-media URI  → follow it (handler unwraps)
 *  - several playlist-like URIs → rewrite as a master so hls.js doesn't try
 *    to demux the inner .m3u8 as a media segment
 */
export function isWrapperManifest(text: string, baseUrl: string): boolean {
  if (!looksLikeHls(text)) return false;
  if (/#EXT-X-STREAM-INF/i.test(text) || /#EXT-X-TARGETDURATION/i.test(text)) return false;
  const uris = listUriLines(text, baseUrl);
  if (uris.length === 0) return false;
  if (uris.some((u) => isObviousMediaUrl(u))) return false;
  if (uris.length === 1) return true;
  return uris.every((u) => looksLikePlaylistUrl(u));
}

/** First URI of a wrapper playlist, already resolved. */
export function firstWrapperUri(text: string, baseUrl: string): string | null {
  return listUriLines(text, baseUrl)[0] ?? null;
}

/**
 * Turn an EXTINF-wrapper into a real HLS master so players treat each URI as
 * a variant playlist, not a media segment.
 */
export function convertWrapperToMaster(text: string): string {
  const lines = text.replace(/\r/g, '').split('\n');
  const out: string[] = ['#EXTM3U'];
  let pendingName = '';
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith('#EXTM3U')) continue;
    if (line.startsWith('#EXTINF')) {
      const comma = line.lastIndexOf(',');
      pendingName = (comma >= 0 ? line.slice(comma + 1) : '').trim();
      continue;
    }
    if (line.startsWith('#')) continue;
    if (!line.trim()) continue;
    const name = pendingName.replace(/"/g, "'");
    pendingName = '';
    out.push(name ? `#EXT-X-STREAM-INF:BANDWIDTH=1,NAME="${name}"` : '#EXT-X-STREAM-INF:BANDWIDTH=1');
    out.push(line.trim());
  }
  return out.join('\n') + '\n';
}

/**
 * A PHP proxy sometimes returns the inner URL as a single plain-text line
 * instead of an M3U. Treat that as a one-hop wrapper.
 */
export function looksLikeBareUpstreamUrl(text: string): string | null {
  const t = text.trim();
  if (!t || t.length > 2048 || /[\r\n<>]/.test(t)) return null;
  if (!/^https?:\/\/\S+$/i.test(t)) return null;
  return t;
}

export interface RewriteOptions {
  secret: string;
  /** Final upstream URL after redirects — base for relative URI resolution. */
  baseUrl: string;
  /** Public origin of this worker, e.g. https://tv.example.com */
  publicOrigin: string;
  /** Identity inherited from the parent token. */
  binding?: TokenBinding;
  /** Channel id inherited for circuit-breaker/failure attribution. */
  channelId?: string;
  /** Parent capability boundary; descendants must never outlive it. */
  absoluteExpiry?: number;
  now?: number;
  /** Inherited upstream request hints. */
  rf?: string;
  ua?: string;
  xh?: string;
}

function mintOpts(opts: RewriteOptions): MintOptions {
  return {
    secret: opts.secret,
    publicOrigin: opts.publicOrigin,
    binding: opts.binding,
    ...(opts.channelId ? { channelId: opts.channelId } : {}),
    ...(opts.absoluteExpiry !== undefined ? { absoluteExpiry: opts.absoluteExpiry } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.rf ? { rf: opts.rf } : {}),
    ...(opts.ua ? { ua: opts.ua } : {}),
    ...(opts.xh ? { xh: opts.xh } : {}),
  };
}

async function tokenUrl(opts: RewriteOptions, upstream: string, kind: 'm' | 's'): Promise<string> {
  try {
    return await mintProxyUrl(mintOpts(opts), upstream, kind);
  } catch (err) {
    throw new HlsError(err instanceof MintError ? err.message : 'token mint failed');
  }
}

async function rewriteAttrUri(
  line: string,
  opts: RewriteOptions,
  kind: 'm' | 's',
  promoteManifestByExtension = false,
): Promise<string> {
  // Match the exact URI attribute, not SERVER-URI or another attribute whose
  // name merely ends in "URI". HLS URI attribute values are quoted strings.
  const m = line.match(/(^|[:,])(\s*)URI="([^"]*)"/);
  if (!m) {
    if (/(^|[:,])\s*URI=/i.test(line)) throw new HlsError('invalid manifest URI attribute');
    return line;
  }
  const uri = m[3];
  if (!uri) throw new HlsError('empty manifest URI');
  const abs = resolveUri(uri, opts.baseUrl);
  if (!abs) throw new HlsError('invalid manifest URI');
  // HLS tag semantics beat filename extensions. Some relays serve keys, maps,
  // parts, and even MPEG-TS segments through an `index.m3u8?u=…` endpoint. If
  // those known media resources are promoted to manifest tokens solely because
  // the endpoint ends in .m3u8, /hls will parse binary media as text and return
  // the empty fallback forever. The extension heuristic remains only for an
  // unknown/future URI-bearing tag where no stronger semantic signal exists.
  const tokenKind = kind === 'm' || (promoteManifestByExtension && isManifestUrl(abs)) ? 'm' : 's';
  const proxied = await tokenUrl(opts, abs, tokenKind);
  return line.replace(m[0], `${m[1]}${m[2]}URI="${proxied}"`);
}

/**
 * Rewrite an HLS manifest so all URIs point back through CHRTV.
 * Throws HlsError for oversized or non-HLS input.
 */
export async function rewriteManifest(text: string, opts: RewriteOptions): Promise<string> {
  if (text.length > MAX_MANIFEST_BYTES) throw new HlsError('manifest too large');
  if (!looksLikeHls(text)) throw new HlsError('not an HLS manifest');

  // Leftover EXTINF-wrappers (multi-URL, or a single URL we chose not to
  // follow) become a real master so hls.js never tries to play an inner
  // .m3u8 / .php playlist as a media segment.
  const source = isWrapperManifest(text, opts.baseUrl) ? convertWrapperToMaster(text) : text;

  const lines = source.replace(/\r/g, '').split('\n');
  const out: string[] = [];
  let nextIsChildManifest = false;

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith('#')) {
      if (line.startsWith('#EXT-X-STREAM-INF')) {
        nextIsChildManifest = true;
        out.push(line);
        continue;
      }
      const tag = line.split(':', 1)[0] ?? '';
      if (MANIFEST_URI_TAGS.includes(tag)) {
        out.push(await rewriteAttrUri(line, opts, 'm'));
        continue;
      }
      if (MEDIA_URI_TAGS.includes(tag)) {
        out.push(await rewriteAttrUri(line, opts, 's'));
        continue;
      }
      // Future/draft HLS tags with an exact URI attribute must not become an
      // upstream-URL escape hatch. Rewrite conservatively as media (promoted to
      // a child manifest when its extension identifies one). Content steering
      // uses SERVER-URI and returns another document containing URLs; reject it
      // until CHRTV can recursively rewrite that document as well.
      if (/(^|[:,])\s*URI=/i.test(line)) {
        out.push(await rewriteAttrUri(line, opts, 's', true));
        continue;
      }
      if (/\bSERVER-URI=/i.test(line)) throw new HlsError('unsupported manifest URI attribute');
      out.push(line);
      continue;
    }
    if (line.trim() === '') {
      out.push(line);
      continue;
    }
    // URI line (segment or child playlist). HLS context is authoritative:
    // a variant URI follows EXT-X-STREAM-INF; every other URI line is media.
    // Do not infer from `.m3u8` here — playnow-style relays deliberately use an
    // index.m3u8 endpoint for binary segment requests distinguished by `?u=`.
    // Wrapper playlists have already been converted to STREAM-INF masters.
    const abs = resolveUri(line.trim(), opts.baseUrl);
    if (!abs) throw new HlsError('invalid manifest URI');
    const kind: 'm' | 's' = nextIsChildManifest ? 'm' : 's';
    nextIsChildManifest = false;
    const proxied = await tokenUrl(opts, abs, kind);
    out.push(proxied);
  }
  return out.join('\n');
}
