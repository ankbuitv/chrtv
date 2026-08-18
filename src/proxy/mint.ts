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
import { kindFromUrl } from '../playlist/playOpts';

/**
 * Shared token-URL mint used by the HLS and DASH rewriters.
 * Every descendant URI becomes an opaque CHRTV capability:
 *   child HLS  → /hls/{token}.m3u8
 *   child MPD  → /mpd/{token}.mpd
 *   media      → /seg/{token}[.ext]
 *   DASH base  → /dseg/{token}/   (path suffix appended by the player)
 */

export type ProxyKind = 'm' | 's' | 'b';

export interface MintOptions {
  secret: string;
  publicOrigin: string;
  binding?: TokenBinding;
  channelId?: string;
  absoluteExpiry?: number;
  now?: number;
  /** Inherited upstream request hints (Referer / UA / extra headers). */
  rf?: string;
  ua?: string;
  xh?: string;
}

export class MintError extends Error {}

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

export async function mintProxyUrl(opts: MintOptions, upstream: string, kind: ProxyKind): Promise<string> {
  if (!isSafeUpstreamUrl(upstream)) throw new MintError('unsafe manifest URI');
  if (!isFetchablePort(upstream)) throw new MintError('unsupported manifest URI port');
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const ttl = kind === 'm' ? DEFAULT_MANIFEST_TTL : SEGMENT_TTL;
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
    k: kind === 'b' ? 'b' : kind,
    ...(opts.channelId ? { c: opts.channelId } : {}),
    ...binding,
    ...(opts.rf ? { rf: opts.rf } : {}),
    ...(opts.ua ? { ua: opts.ua } : {}),
    ...(opts.xh ? { xh: opts.xh } : {}),
  };
  const token = await createToken(
    opts.secret,
    payload,
    `${kind}|${iat}|${exp}|${upstream}|${opts.channelId ?? ''}|${tokenBindingSeed(binding)}|${opts.rf ?? ''}|${opts.ua ?? ''}|${opts.xh ?? ''}`,
  );
  if (kind === 'b') return `${opts.publicOrigin}/dseg/${token}/`;
  if (kind === 'm') {
    if (kindFromUrl(upstream) === 'mpd') return `${opts.publicOrigin}/mpd/${token}.mpd`;
    return `${opts.publicOrigin}/hls/${token}.m3u8`;
  }
  const ext = extOf(upstream);
  return `${opts.publicOrigin}/seg/${token}${ext ? '.' + ext : ''}`;
}
