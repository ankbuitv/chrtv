import { getAesKey, base64UrlEncode, base64UrlDecode, hmacHex } from '../utils/crypto';
import { normalizeMac } from '../utils/mac';
import { isSafeUpstreamUrl } from '../utils/urlsafe';

/**
 * Opaque AES-256-GCM stream tokens.
 * Payload: { u: upstream URL, iat, exp, k?: kind, ...optional binding }.
 * GCM gives confidentiality + tamper resistance (auth tag); the IV is carried
 * in the token itself. Tokens never reveal the upstream URL or identity claims.
 *
 * Two IV modes:
 *  - random (default) — one-off mints.
 *  - deterministic (`seed`) — playlist entries and URIs inside a live manifest.
 *    A player re-fetches playlists every few seconds; a stable token lets it
 *    retain channel mappings and de-duplicate already-buffered segments.
 *
 * In deterministic mode the IV is derived from both the caller's stable seed
 * and the serialized payload. A changed expiry, URL, or identity therefore gets
 * a different IV automatically; GCM never reuses an IV for different plaintext.
 */

/** Identity attached to a stream token. All fields are encrypted by GCM. */
export interface TokenBinding {
  /** Cloudflare-observed client IP. Enforced on every /hls and /seg request. */
  ip?: string;
  /** Normalized, client-declared MAC. Personalizes the token; see note below. */
  mac?: string;
  /** Authenticated D1 user id. */
  uid?: number;
  /** Authenticated access-key id. */
  aid?: number;
  /** Opaque-login session id; authorization is rechecked on manifest/EPG access. */
  sid?: number;
}

export interface TokenPayload extends TokenBinding {
  /** Upstream URL */
  u: string;
  /** Issued-at (unix seconds) */
  iat: number;
  /** Expiry (unix seconds) */
  exp: number;
  /** Resource kind hint: m=manifest, s=segment/media, e=tokenized EPG */
  k?: 'm' | 's' | 'e';
  /** Channel id (set on channel and descendant manifest/media tokens) */
  c?: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const DEFAULT_MANIFEST_TTL = 6 * 60 * 60; // channel entries in playlists
export const SEGMENT_TTL = 60 * 60; // segment/child-manifest URIs inside manifests

/** Window used to quantize `iat` so repeated rewrites produce identical tokens. */
export const TOKEN_STABILITY_WINDOW = 10 * 60;

/**
 * Read the client address from Cloudflare's trusted edge header.
 * X-Forwarded-For is intentionally ignored because clients can spoof it.
 */
export function getClientIp(req: Request): string | undefined {
  const raw = req.headers.get('CF-Connecting-IP')?.trim();
  if (!raw || raw.length > 64 || !/^[0-9a-f:.]+$/i.test(raw)) return undefined;
  return raw.toLowerCase();
}

export interface TokenBindingPolicy {
  ip: boolean;
  mac: boolean;
  user: boolean;
  key: boolean;
}

const DEFAULT_BINDING_POLICY: TokenBindingPolicy = { ip: true, mac: true, user: true, key: true };
const BINDING_POLICY_NAMES = new Set(['ip', 'mac', 'user', 'key']);

/**
 * Parse TOKEN_BINDING (`ip,mac,user,key` by default; `none` disables claims).
 * Invalid configurations fail closed to the secure default instead of silently
 * turning binding off because of a typo.
 */
export function parseTokenBindingPolicy(configured?: string): TokenBindingPolicy {
  if (!configured?.trim()) return { ...DEFAULT_BINDING_POLICY };
  const names = configured
    .toLowerCase()
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean);
  if (names.length === 1 && names[0] === 'none') return { ip: false, mac: false, user: false, key: false };
  if (names.length === 0 || names.some((name) => !BINDING_POLICY_NAMES.has(name))) return { ...DEFAULT_BINDING_POLICY };
  const enabled = new Set(names);
  return {
    ip: enabled.has('ip'),
    mac: enabled.has('mac'),
    user: enabled.has('user'),
    key: enabled.has('key'),
  };
}

/** Build a compact, normalized identity for newly minted stream tokens. */
export function requestTokenBinding(
  req: Request,
  options: { rawMac?: string | null; userId?: number | null; accessKeyId?: number | null; sessionId?: number | null } = {},
  configuredPolicy?: string,
): TokenBinding {
  const policy = parseTokenBindingPolicy(configuredPolicy);
  const binding: TokenBinding = {};
  const ip = policy.ip ? getClientIp(req) : undefined;
  const mac = policy.mac ? normalizeMac(options.rawMac ?? null) : null;
  if (ip) binding.ip = ip;
  if (mac) binding.mac = mac;
  if (policy.user && Number.isSafeInteger(options.userId) && (options.userId ?? 0) > 0) binding.uid = options.userId!;
  if (policy.key && Number.isSafeInteger(options.accessKeyId) && (options.accessKeyId ?? 0) > 0) binding.aid = options.accessKeyId!;
  // Session authorization is a capability check, not an optional identity-
  // binding policy. Keep its ownership claims even when TOKEN_BINDING=none so
  // account/session revocation still works.
  if (Number.isSafeInteger(options.sessionId) && (options.sessionId ?? 0) > 0) {
    if (Number.isSafeInteger(options.userId) && (options.userId ?? 0) > 0) binding.uid = options.userId!;
    binding.sid = options.sessionId!;
  }
  return binding;
}

/** Copy only identity claims from a verified token into descendant tokens. */
export function tokenBindingFromPayload(payload: TokenPayload): TokenBinding {
  const binding: TokenBinding = {};
  if (payload.ip) binding.ip = payload.ip;
  if (payload.mac) binding.mac = payload.mac;
  if (payload.uid !== undefined) binding.uid = payload.uid;
  if (payload.aid !== undefined) binding.aid = payload.aid;
  if (payload.sid !== undefined) binding.sid = payload.sid;
  return binding;
}

/** Stable seed fragment; keeps deterministic IVs unique per identity. */
export function tokenBindingSeed(binding: TokenBinding | undefined): string {
  if (!binding) return '-';
  return [binding.ip ?? '', binding.mac ?? '', binding.uid ?? '', binding.aid ?? '', binding.sid ?? ''].join('|');
}

/**
 * Enforce claims the server can independently observe.
 *
 * A remote HTTP server cannot read a device's layer-2 hardware MAC. `mac` is
 * therefore an encrypted, client-declared device identity used to personalize
 * tokens and tie them to access-key device registration; it is not treated as
 * a standalone authenticator. IP, on the other hand, is supplied by
 * Cloudflare and is strictly checked here.
 */
export function requestMatchesTokenBinding(req: Request, payload: TokenPayload): boolean {
  if (!payload.ip) return true;
  return getClientIp(req) === payload.ip;
}

async function deterministicIv(secret: string, seed: string): Promise<Uint8Array> {
  const hex = await hmacHex(secret, `iv|${seed}`);
  const iv = new Uint8Array(12);
  for (let i = 0; i < 12; i++) iv[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return iv;
}

export async function createToken(secret: string, payload: TokenPayload, seed?: string): Promise<string> {
  const key = await getAesKey(secret);
  const serialized = JSON.stringify(payload);
  let iv: Uint8Array;
  if (seed) {
    // Include plaintext in the derivation defensively: even if a future caller
    // forgets to add a new payload field to its seed, different GCM plaintexts
    // can never end up using the same key+IV pair.
    iv = await deterministicIv(secret, `${seed}|payload|${serialized}`);
  } else {
    iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
  }
  const plain = encoder.encode(serialized);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  const packed = new Uint8Array(iv.length + cipher.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(cipher), iv.length);
  return base64UrlEncode(packed);
}

export type TokenResult =
  | { ok: true; payload: TokenPayload }
  | { ok: false; code: 'TOKEN_INVALID' | 'TOKEN_EXPIRED' | 'UNSAFE_URL' };

function validOptionalClaims(payload: TokenPayload): boolean {
  if (payload.k !== undefined && payload.k !== 'm' && payload.k !== 's' && payload.k !== 'e') return false;
  if (payload.c !== undefined && (typeof payload.c !== 'string' || payload.c.length > 128)) return false;
  if (payload.ip !== undefined && (typeof payload.ip !== 'string' || payload.ip.length > 64 || !/^[0-9a-f:.]+$/i.test(payload.ip))) {
    return false;
  }
  if (payload.mac !== undefined && (typeof payload.mac !== 'string' || normalizeMac(payload.mac) !== payload.mac)) return false;
  if (payload.uid !== undefined && (!Number.isSafeInteger(payload.uid) || payload.uid <= 0)) return false;
  if (payload.aid !== undefined && (!Number.isSafeInteger(payload.aid) || payload.aid <= 0)) return false;
  if (payload.sid !== undefined && (!Number.isSafeInteger(payload.sid) || payload.sid <= 0)) return false;
  // Every login session belongs to a user. Requiring the encrypted user claim
  // also prevents a malformed session-only token from bypassing ownership.
  if (payload.sid !== undefined && payload.uid === undefined) return false;
  if (payload.sid !== undefined && payload.aid !== undefined) return false;
  return true;
}

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
  let decoded: unknown;
  try {
    const key = await getAesKey(secret);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    decoded = JSON.parse(decoder.decode(plainBuf)) as unknown;
  } catch {
    return { ok: false, code: 'TOKEN_INVALID' };
  }
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) return { ok: false, code: 'TOKEN_INVALID' };
  const payload = decoded as TokenPayload;
  if (
    typeof payload.u !== 'string' ||
    typeof payload.exp !== 'number' ||
    !Number.isFinite(payload.exp) ||
    typeof payload.iat !== 'number' ||
    !Number.isFinite(payload.iat) ||
    !validOptionalClaims(payload)
  ) {
    return { ok: false, code: 'TOKEN_INVALID' };
  }
  if (payload.exp <= now) return { ok: false, code: 'TOKEN_EXPIRED' };
  if (!isSafeUpstreamUrl(payload.u)) return { ok: false, code: 'UNSAFE_URL' };
  return { ok: true, payload };
}
