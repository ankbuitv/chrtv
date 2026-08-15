/**
 * SSRF guard for upstream URLs.
 * Upstream URLs only ever come from the D1 channel table or from CHRTV-issued
 * encrypted tokens (which themselves are minted from validated manifests) —
 * but validate again right before every fetch (defense in depth).
 */

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'instance-data',
]);

function isPrivateIpv4(host: string): boolean {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const oct = m.slice(1).map(Number);
  if (oct.some((o) => o > 255)) return true; // malformed => treat as unsafe
  const [a, b] = oct as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIpv6(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('fe80') || h.startsWith('fc') || h.startsWith('fd')) return true;
  if (h.startsWith('::ffff:')) return isPrivateIpv4(h.slice(7));
  return false;
}

/** Returns true when the URL is a safe http(s) upstream target. */
export function isSafeUpstreamUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (!host) return false;
  if (BLOCKED_HOSTNAMES.has(host)) return false;
  if (host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (!host.includes('.') && !host.includes(':')) return false; // bare intranet hostnames
  if (host.includes(':') || /^\[/.test(url.hostname)) {
    if (isPrivateIpv6(url.hostname)) return false;
  }
  if (isPrivateIpv4(host)) return false;
  // Decimal/hex/octal single-number IPv4 forms (e.g. http://2130706433/)
  if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/.test(host)) return false;
  return true;
}
