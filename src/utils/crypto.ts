const encoder = new TextEncoder();

/** Module-level CryptoKey cache — safe: keys derive only from the worker secret. */
const keyCache = new Map<string, Promise<CryptoKey>>();

function cachedKey(cacheId: string, make: () => Promise<CryptoKey>): Promise<CryptoKey> {
  let p = keyCache.get(cacheId);
  if (!p) {
    p = make();
    keyCache.set(cacheId, p);
  }
  return p;
}

export function getHmacKey(secret: string): Promise<CryptoKey> {
  return cachedKey(`hmac:${secret}`, () =>
    crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
  );
}

export function getAesKey(secret: string): Promise<CryptoKey> {
  return cachedKey(`aes:${secret}`, async () => {
    const material = await crypto.subtle.digest('SHA-256', encoder.encode(`chrtv-token|${secret}`));
    return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  });
}

export function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await getHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return bytesToHex(sig);
}

export async function sha256Hex(data: string): Promise<string> {
  return bytesToHex(await crypto.subtle.digest('SHA-256', encoder.encode(data)));
}

/**
 * Keyed password hash: HMAC-SHA256(SECRET_KEY, salt:password).
 * Offline cracking requires the worker secret; cheap enough for the hot stream path.
 */
export function hashPassword(secret: string, salt: string, password: string): Promise<string> {
  return hmacHex(secret, `pw|${salt}|${password}`);
}

/** Keyed access-key hash — the raw key is never stored. */
export function hashAccessKey(secret: string, key: string): Promise<string> {
  return hmacHex(secret, `ak|${key}`);
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

/** Constant-time string comparison (content-independent timing; length may leak, which is fine here). */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = encoder.encode(a);
  const bb = encoder.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(text: string): Uint8Array {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
