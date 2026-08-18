import {
  createToken,
  SEGMENT_TTL,
  DEFAULT_MANIFEST_TTL,
  TOKEN_STABILITY_WINDOW,
  tokenBindingSeed,
  type TokenBinding,
  type TokenPayload,
} from '../token';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';

/**
 * HLS manifest rewriter.
 * Every URI (line URIs and attribute URI="..." in tags) is resolved against the
 * FINAL upstream URL (post-redirect) and replaced by a CHRTV token URL:
 *   child manifests -> /hls/{token}.m3u8
 *   media/keys/maps -> /seg/{token}[.ext]
 * Any resolved URL that cannot be safely proxied rejects the manifest rather
 * than leaking a direct URI. URLs on ports Cloudflare Workers cannot fetch are
 * rejected too — unless `allowDirectOrigin` is set, in which case they are left
 * as direct origin URLs so the player (an ordinary client, able to open any
 * port) can fetch them itself while the Worker keeps proxying the fetchable
 * parts of a mixed-port manifest.
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
  /** Identity inherited from the parent token. */
  binding?: TokenBinding;
  /**
   * When true, URIs on ports the Worker cannot fetch are emitted as direct
   * origin URLs instead of rejecting the manifest. Players can open any port,
   * so mixed-port manifests keep playing while the fetchable URIs stay proxied
   * through CHRTV. When false/absent, such URIs reject the whole manifest
   * (fail closed, strict origin hiding).
   */
  allowDirectOrigin?: boolean;
  /** Channel id inherited for circuit-breaker/failure attribution. */
  channelId?: string;
  /** Parent capability boundary; descendants must never outlive it. */
  absoluteExpiry?: number;
  now?: number;
}

async function tokenUrl(opts: RewriteOptions, upstream: string, kind: 'm' | 's'): Promise<string> {
  if (!isSafeUpstreamUrl(upstream)) throw new HlsError('unsafe manifest URI');
  if (!isFetchablePort(upstream)) {
    // The Worker can never proxy this URI. With allowDirectOrigin the raw URL
    // is left in place so the player fetches it directly; otherwise the whole
    // manifest is rejected before any dead child capability is issued.
    if (opts.allowDirectOrigin) return upstream;
    throw new HlsError('unsupported manifest URI port');
  }
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const ttl = kind === 'm' ? DEFAULT_MANIFEST_TTL : SEGMENT_TTL;
  // Quantized issue time + deterministic IV => the same upstream URI keeps the
  // same proxied URL across manifest refreshes, so players reuse their buffer
  // instead of re-downloading every segment. Identity is included in the seed,
  // which both personalizes URLs and prevents deterministic GCM IV reuse across
  // different payloads.
  const iat = Math.floor(now / TOKEN_STABILITY_WINDOW) * TOKEN_STABILITY_WINDOW;
  const binding = opts.binding ?? {};
  const configuredExp = iat + ttl;
  const exp =
    opts.absoluteExpiry !== undefined && Number.isFinite(opts.absoluteExpiry)
      ? Math.min(configuredExp, Math.floor(opts.absoluteExpiry))
      : configuredExp;
  const payload: TokenPayload = {
    u: upstream,
    iat,
    exp,
    k: kind,
    ...(opts.channelId ? { c: opts.channelId } : {}),
    ...binding,
  };
  const token = await createToken(
    opts.secret,
    payload,
    `${kind}|${iat}|${exp}|${upstream}|${opts.channelId ?? ''}|${tokenBindingSeed(binding)}`,
  );
  if (kind === 'm') return `${opts.publicOrigin}/hls/${token}.m3u8`;
  const ext = extOf(upstream);
  return `${opts.publicOrigin}/seg/${token}${ext ? '.' + ext : ''}`;
}

async function rewriteAttrUri(line: string, opts: RewriteOptions, kind: 'm' | 's'): Promise<string> {
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
  const proxied = await tokenUrl(opts, abs, kind === 'm' || isManifestUrl(abs) ? 'm' : 's');
  return line.replace(m[0], `${m[1]}${m[2]}URI="${proxied}"`);
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
      // Future/draft HLS tags with an exact URI attribute must not become an
      // upstream-URL escape hatch. Rewrite conservatively as media (promoted to
      // a child manifest when its extension identifies one). Content steering
      // uses SERVER-URI and returns another document containing URLs; reject it
      // until CHRTV can recursively rewrite that document as well.
      if (/(^|[:,])\s*URI=/i.test(line)) {
        out.push(await rewriteAttrUri(line, opts, 's'));
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
    // URI line (segment or child playlist)
    const abs = resolveUri(line.trim(), opts.baseUrl);
    if (!abs) throw new HlsError('invalid manifest URI');
    const kind: 'm' | 's' = nextIsChildManifest || isManifestUrl(abs) ? 'm' : 's';
    nextIsChildManifest = false;
    const proxied = await tokenUrl(opts, abs, kind);
    out.push(proxied);
  }
  return out.join('\n');
}
