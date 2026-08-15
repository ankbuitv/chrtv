/**
 * Cloudflare Workers can only open subrequests to a fixed set of ports.
 * A fetch to any other port is silently rewritten to 80/443 (or simply resets),
 * which shows up in players as random stalls / "connection is unstable".
 * We therefore refuse such URLs up-front instead of burning a 30s timeout
 * on every single request.
 *
 * https://developers.cloudflare.com/workers/runtime-apis/fetch/
 */

const HTTP_PORTS = new Set([80, 8080, 8880, 2052, 2082, 2086, 2095]);
const HTTPS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);

/** True when a Worker subrequest to this URL can actually reach the given port. */
export function isFetchablePort(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (!url.port) return true; // default 80/443
  const port = Number(url.port);
  if (!Number.isInteger(port)) return false;
  return url.protocol === 'https:' ? HTTPS_PORTS.has(port) : HTTP_PORTS.has(port);
}
