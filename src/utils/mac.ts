const MAC_RE = /^[0-9A-F]{12}$/;

/**
 * Normalize a MAC address to AA:BB:CC:DD:EE:FF.
 * Accepts ":", "-", "." separators or bare hex. Returns null when invalid.
 */
export function normalizeMac(input: string | null | undefined): string | null {
  if (!input) return null;
  const hex = input.trim().toUpperCase().replace(/[:\-.\s]/g, '');
  if (!MAC_RE.test(hex)) return null;
  const parts: string[] = [];
  for (let i = 0; i < 12; i += 2) parts.push(hex.slice(i, i + 2));
  return parts.join(':');
}
