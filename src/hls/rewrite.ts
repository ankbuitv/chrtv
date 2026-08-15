import { createToken, SEGMENT_TTL, DEFAULT_MANIFEST_TTL, TOKEN_STABILITY_WINDOW, type TokenPayload } from '../token';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';

/**
 * HLS manifest rewriter.
 * Every URI (line URIs and attribute URI="..." in tags) is resolved against the
 * FINAL upstream URL (post-redirect) and replaced by a CHRTV token URL:
 *   child manifests -> /hls/{token}.m3u8
 *   media/keys/maps -> /seg/{token}[.ext]
 * Unsafe resolved URLs (private IPs etc.) are dropped rather than proxied.
 */

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

// Tags whose URI attribute points to another *playlist*.
const MANIFEST_URI_TAGS = ['#EXT-X-MEDIA', '#EXT-X-I-FRAME-STREAM-INF'];
// Tags whose URI attribute points to *media* (segments, keys, init sections, parts).
const MEDIA_URI_TAGS = ['#EXT-X-KEY', '#EXT-X-SESSION-KEY', '#EXT-X-MAP', '#EXT-X-PART', '#EXT-X-PRELOAD-HINT'];

export class HlsError extends Error {}

export function looksLikeHls(text: string): boolean {
  return text.trimStart().startsWith('#EXTM3U');
}

function resolveUri(uri: string, baseUrl: string): string | null {
  try {
    // URL() handles absolute, protocol-relative (//host/x), relative paths,
    // query strings and fragments.
    return new URL(uri, baseUrl).toString();
  } catch {
    return null;
  }
}

function extOf(url: string): string {
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

function isManifestUrl(url: string): boolean {
  const e = extOf(url);
  return e === 'm3u8' || e === 'm3u';
}

export interface RewriteOptions {
  secret: string;
  /** Final upstream URL after redirects — base for relative URI resolution. */
  baseUrl: string;
  /** Public origin of this worker, e.g. https://tv.example.com */
  publicOrigin: string;
  now?: number;
}

async function tokenUrl(opts: RewriteOptions, upstream: string, kind: 'm' | 's'): Promise<string | null> {
  if (!isSafeUpstreamUrl(upstream)) return null;
  // A URL on a port Workers cannot reach would silently hit :80/:443 and stall.
  if (!isFetchablePort(upstream)) return null;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const ttl = kind === 'm' ? DEFAULT_MANIFEST_TTL : SEGMENT_TTL;
  // Quantized issue time + deterministic IV => the same upstream URI keeps the
  // same proxied URL across manifest refreshes, so players reuse their buffer
  // instead of re-downloading every segment (the "connection is unstable" loop).
  const iat = Math.floor(now / TOKEN_STABILITY_WINDOW) * TOKEN_STABILITY_WINDOW;
  const payload: TokenPayload = { u: upstream, iat, exp: iat + ttl, k: kind };
  const token = await createToken(opts.secret, payload, `${kind}|${iat}|${upstream}`);
  if (kind === 'm') return `${opts.publicOrigin}/hls/${token}.m3u8`;
  const ext = extOf(upstream);
  return `${opts.publicOrigin}/seg/${token}${ext ? '.' + ext : ''}`;
}

async function rewriteAttrUri(line: string, opts: RewriteOptions, kind: 'm' | 's'): Promise<string> {
  const m = line.match(/URI="([^"]*)"/);
  if (!m || !m[1]) return line;
  const abs = resolveUri(m[1], opts.baseUrl);
  if (!abs) return line;
  const proxied = await tokenUrl(opts, abs, kind === 'm' || isManifestUrl(abs) ? 'm' : 's');
  if (!proxied) return line; // unsafe -> leave untouched (will 404 at player, never proxied)
  return line.replace(m[0], `URI="${proxied}"`);
}

/**
 * Rewrite an HLS manifest so all URIs point back through CHRTV.
 * Throws HlsError for oversized or non-HLS input.
 */
export async function rewriteManifest(text: string, opts: RewriteOptions): Promise<string> {
  if (text.length > MAX_MANIFEST_BYTES) throw new HlsError('manifest too large');
  if (!looksLikeHls(text)) throw new HlsError('not an HLS manifest');

  const lines = text.replace(/\r/g, '').split('\n');
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
      out.push(line);
      continue;
    }
    if (line.trim() === '') {
      out.push(line);
      continue;
    }
    // URI line (segment or child playlist)
    const abs = resolveUri(line.trim(), opts.baseUrl);
    if (!abs) {
      out.push(line);
      nextIsChildManifest = false;
      continue;
    }
    const kind: 'm' | 's' = nextIsChildManifest || isManifestUrl(abs) ? 'm' : 's';
    nextIsChildManifest = false;
    const proxied = await tokenUrl(opts, abs, kind);
    out.push(proxied ?? line);
  }
  return out.join('\n');
}
