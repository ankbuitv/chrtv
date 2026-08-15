import { getAesKey, base64UrlEncode, base64UrlDecode } from '../utils/crypto';
import { isSafeUpstreamUrl } from '../utils/urlsafe';

/**
 * Opaque AES-256-GCM stream tokens.
 * Payload: { u: upstream URL, iat, exp, k?: kind }.
 * GCM gives confidentiality + tamper resistance (auth tag); the random IV is
 * carried in the token itself. Tokens never reveal the upstream URL.
 */

export interface TokenPayload {
  /** Upstream URL */
  u: string;
  /** Issued-at (unix seconds) */
  iat: number;
  /** Expiry (unix seconds) */
  exp: number;
  /** Resource kind hint: m=manifest, s=segment/media */
  k?: 'm' | 's';
  /** Channel id (only set on channel-level manifest tokens) */
  c?: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const DEFAULT_MANIFEST_TTL = 6 * 60 * 60; // channel entries in playlists
export const SEGMENT_TTL = 15 * 60; // segment/child-manifest URIs inside manifests

export async function createToken(secret: string, payload: TokenPayload): Promise<string> {
  const key = await getAesKey(secret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plain = encoder.encode(JSON.stringify(payload));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  const packed = new Uint8Array(iv.length + cipher.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(cipher), iv.length);
  return base64UrlEncode(packed);
}

export type TokenResult =
  | { ok: true; payload: TokenPayload }
  | { ok: false; code: 'TOKEN_INVALID' | 'TOKEN_EXPIRED' | 'UNSAFE_URL' };

export async function verifyToken(secret: string, token: string, now = Math.floor(Date.now() / 1000)): Promise<TokenResult> {
  if (!token || token.length > 4096) return { ok: false, code: 'TOKEN_INVALID' };
  let packed: Uint8Array;
  try {
    packed = base64UrlDecode(token);
  } catch {
    return { ok: false, code: 'TOKEN_INVALID' };
  }
  if (packed.length < 13) return { ok: false, code: 'TOKEN_INVALID' };
  const iv = packed.slice(0, 12);
  const cipher = packed.slice(12);
  let payload: TokenPayload;
  try {
    const key = await getAesKey(secret);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    payload = JSON.parse(decoder.decode(plainBuf)) as TokenPayload;
  } catch {
    return { ok: false, code: 'TOKEN_INVALID' };
  }
  if (typeof payload.u !== 'string' || typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
    return { ok: false, code: 'TOKEN_INVALID' };
  }
  if (payload.exp <= now) return { ok: false, code: 'TOKEN_EXPIRED' };
  if (!isSafeUpstreamUrl(payload.u)) return { ok: false, code: 'UNSAFE_URL' };
  return { ok: true, payload };
}
