/**
 * Circuit breaker for dead upstreams.
 * Hot path uses the Cloudflare Cache API (edge-local, zero D1 cost, per-colo —
 * good enough: the goal is stopping request storms, not global consensus).
 * D1 `stream_failures` keeps a durable log for the admin API.
 * Entries auto-expire via Cache-Control TTL, so channels are never dead forever.
 */

export const FAILURE_TTL_SECONDS = 30;

export interface FailureState {
  code: string;
  status: number;
  at: number;
}

function cacheKey(channelKey: string): Request {
  return new Request(`https://chrtv.internal/failure/${encodeURIComponent(channelKey)}`);
}

export async function getFailure(channelKey: string): Promise<FailureState | null> {
  try {
    const hit = await caches.default.match(cacheKey(channelKey));
    if (!hit) return null;
    return (await hit.json()) as FailureState;
  } catch {
    return null;
  }
}

export async function setFailure(channelKey: string, state: FailureState): Promise<void> {
  try {
    await caches.default.put(
      cacheKey(channelKey),
      new Response(JSON.stringify(state), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${FAILURE_TTL_SECONDS}` },
      }),
    );
  } catch {
    // Cache API unavailable (e.g. some test environments) — breaker becomes a no-op.
  }
}

export async function clearFailure(channelKey: string): Promise<void> {
  try {
    await caches.default.delete(cacheKey(channelKey));
  } catch {
    /* ignore */
  }
}

/** Durable failure record for admin visibility. Never store upstream URLs or headers in `detail`. */
export async function recordFailure(db: D1Database, channelId: string, code: string, status: number): Promise<void> {
  try {
    await db
      .prepare('INSERT INTO stream_failures (channel_id, error_code, http_status, detail, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(channelId, code, status, '', Math.floor(Date.now() / 1000))
      .run();
  } catch {
    // Failure logging must never break the stream path.
  }
}
