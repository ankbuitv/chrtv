import type { Env } from '../types';
import { ErrorCodes } from '../errors/codes';
import { classifyUpstreamStatus } from '../proxy/upstream';
import { isSafeUpstreamUrl } from '../utils/urlsafe';
import { isFetchablePort } from '../utils/ports';
import { looksLikeHls } from '../hls/rewrite';
import { logEvent } from '../utils/http';

/**
 * Proactive channel health checks.
 *
 * The proxy logs failures *reactively* (stream_failures) only when a viewer
 * actually tunes in and the upstream is dead. A broken channel nobody has
 * watched therefore looks perfectly healthy in the playlist forever. This
 * module sweeps upstreams on a schedule and records the LATEST state per
 * channel into `channel_health`, so the admin API can answer "which channels
 * are offline right now?".
 *
 * Each sweep is bounded (oldest-checked active channels first, capped at
 * MAX_PROBES_PER_RUN) so it stays inside the Workers subrequest/time budget.
 *
 * `offline` is reserved for CONFIRMED deaths only — 404/410, 5xx, timeouts,
 * unreachable hosts, or a 200 whose body is not HLS. Everything the probe
 * cannot conclude is `unknown`, never `offline`:
 *  - ports the Worker cannot open a subrequest to (e.g. :30113) are played
 *    directly by the client, so the Worker cannot judge them;
 *  - 401/403/429/451 (auth / geo-block / rate-limit) depend on WHERE the probe
 *    runs. Cron triggers fire on an arbitrary Cloudflare colo, possibly
 *    outside the audience's country, so a 403 seen by the sweep proves nothing
 *    about what viewers see. Flagging those offline is how a healthy playlist
 *    ends up "toàn offline".
 */

export type HealthStatus = 'online' | 'offline' | 'unknown';

export interface ProbeResult {
  status: HealthStatus;
  errorCode: string;
  httpStatus: number;
}

export interface HealthCheckSummary {
  checked: number;
  online: number;
  offline: number;
  unknown: number;
}

export interface OfflineChannel {
  channel_id: string;
  name: string;
  xtream_id: number;
  category: string | null;
  error_code: string;
  http_status: number;
  checked_at: number;
}

export interface HealthStats {
  online: number;
  offline: number;
  unknown: number;
  /** % of *checked* channels that are offline (0 when nothing has been checked). */
  offline_ratio: number;
  /** unix seconds of the most recent probe across all channels; 0 if never. */
  last_checked: number;
}

const PROBE_TIMEOUT_MS = 6_000;
const MAX_REDIRECTS = 3;
const PROBE_PREFIX_BYTES = 64 * 1024;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Hard ceiling on probes per invocation.
 *
 * Cloudflare Workers caps subrequests per invocation at 50 on the Free plan
 * (1,000 paid). Every probe costs 1 fetch plus up to MAX_REDIRECTS more when
 * the upstream redirects (very common: relays like devda.undo.it bounce to
 * the real CDN). Exceeding the cap makes every fetch PAST the limit throw a
 * plain network error — which the old code counted as "offline". A batch of
 * 100 therefore silently flagged dozens of perfectly healthy channels offline
 * on every sweep, until the whole playlist read "offline".
 *
 * 12 probes × worst-case (1 + 3) fetches = 48 subrequests < 50. Paid-plan
 * operators may raise this safely.
 */
export const MAX_PROBES_PER_RUN = 12;
/** Concurrency used inside a sweep — gentle on upstreams, caps tail latency. */
const PROBE_CONCURRENCY = 8;
/** Default sweep size for the periodic cron trigger. */
export const DEFAULT_HEALTH_BATCH = MAX_PROBES_PER_RUN;

async function readPrefix(res: Response, max: number): Promise<string> {
  try {
    const reader = res.body?.getReader();
    if (!reader) return '';
    const dec = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false });
    let buf = '';
    while (buf.length < max) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
    }
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
    return buf.slice(0, max);
  } catch {
    return '';
  }
}

/**
 * Probe a single upstream URL and classify its health.
 * Reuses the proxy's SSRF + port-safety checks at every hop, follows redirects
 * manually, and — crucially — confirms a 2xx body actually looks like HLS so a
 * "200 + HTML error page" broken link is correctly flagged offline.
 */
export async function probeChannel(url: string): Promise<ProbeResult> {
  if (!isSafeUpstreamUrl(url)) return { status: 'unknown', errorCode: ErrorCodes.UNSAFE_URL, httpStatus: 0 };
  if (!isFetchablePort(url)) return { status: 'unknown', errorCode: ErrorCodes.UNSUPPORTED_PORT, httpStatus: 0 };

  let currentUrl = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isSafeUpstreamUrl(currentUrl) || !isFetchablePort(currentUrl)) {
      return { status: 'unknown', errorCode: ErrorCodes.UNSUPPORTED_PORT, httpStatus: 0 };
    }
    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          // A player-flavoured UA: naive anti-leech filters reject "bot/probe/health"
          // user agents, and the sweep should behave like a real viewer anyway.
          'User-Agent': 'VLC/3.0.20 LibVLC/3.0.20',
          Accept: 'application/vnd.apple.mpegurl, audio/mpegurl, */*',
          'Accept-Encoding': 'identity',
        },
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === 'TimeoutError';
      return {
        status: 'offline',
        errorCode: timedOut ? ErrorCodes.UPSTREAM_TIMEOUT : ErrorCodes.UPSTREAM_UNREACHABLE,
        httpStatus: 0,
      };
    }

    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get('Location');
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      if (!location || hop === MAX_REDIRECTS) {
        return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: res.status };
      }
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: res.status };
      }
      continue;
    }

    // Non-2xx reached. Only responses that PROVE the stream is gone are
    // counted as offline; the rest is vantage-point-dependent and stays
    // `unknown` (see module doc). A transient 5xx/timeout self-corrects on
    // the next rotation, a false "offline" flags a healthy channel for hours.
    if (res.status === 404 || res.status === 410) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_404, httpStatus: res.status };
    }
    if (res.status >= 500) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_5XX, httpStatus: res.status };
    }
    if (!res.ok && res.status !== 206) {
      // 401/403/429/451… — auth, geo-block or rate-limit: the channel may be
      // perfectly fine for real viewers. Report as unknown, keep the code.
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 'unknown', errorCode: classifyUpstreamStatus(res.status), httpStatus: res.status };
    }

    const prefix = await readPrefix(res, PROBE_PREFIX_BYTES);
    return looksLikeHls(prefix)
      ? { status: 'online', errorCode: '', httpStatus: res.status }
      : { status: 'offline', errorCode: ErrorCodes.INVALID_HLS, httpStatus: res.status };
  }
  return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: 0 };
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      out[idx] = await fn(items[idx]!, idx);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Probe a bounded batch of active channels and persist their latest health.
 * Selects the OLDEST-checked channels first, so never-checked channels are
 * covered on the first sweep and every channel is re-checked in rotation.
 */
export async function healthCheckBatch(env: Env, limit: number): Promise<HealthCheckSummary> {
  const cap = Math.max(1, Math.min(limit, MAX_PROBES_PER_RUN));
  const { results } = await env.DB
    .prepare(
      `SELECT c.id, c.url
         FROM channels c
         LEFT JOIN channel_health h ON h.channel_id = c.id
        WHERE c.active = 1 AND c.url != ''
        ORDER BY h.checked_at ASC, c.position ASC
        LIMIT ?`,
    )
    .bind(cap)
    .all<{ id: string; url: string }>();

  const probed = await mapWithConcurrency(results, PROBE_CONCURRENCY, async (ch) => ({
    id: ch.id,
    ...(await probeChannel(ch.url)),
  }));

  const now = Math.floor(Date.now() / 1000);
  const stmts = probed.map((r) =>
    env.DB
      .prepare(
        `INSERT INTO channel_health (channel_id, status, error_code, http_status, checked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(channel_id) DO UPDATE SET
           status = excluded.status,
           error_code = excluded.error_code,
           http_status = excluded.http_status,
           checked_at = excluded.checked_at`,
      )
      .bind(r.id, r.status, r.errorCode, r.httpStatus, now),
  );
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));

  const summary: HealthCheckSummary = { checked: probed.length, online: 0, offline: 0, unknown: 0 };
  for (const r of probed) {
    if (r.status === 'online') summary.online++;
    else if (r.status === 'offline') summary.offline++;
    else summary.unknown++;
  }
  return summary;
}

/** Channels currently flagged offline (and still active in the playlist). */
export async function listOfflineChannels(db: D1Database, limit = 500): Promise<OfflineChannel[]> {
  const { results } = await db
    .prepare(
      `SELECT h.channel_id, c.name, c.xtream_id, cat.name AS category,
              h.error_code, h.http_status, h.checked_at
         FROM channel_health h
         JOIN channels c ON c.id = h.channel_id
         LEFT JOIN categories cat ON cat.id = c.category_id
        WHERE h.status = 'offline' AND c.active = 1
        ORDER BY h.checked_at DESC
        LIMIT ?`,
    )
    .bind(limit)
    .all<OfflineChannel>();
  return results;
}

/** Aggregate health counts for the status endpoint. */
export async function healthStats(db: D1Database): Promise<HealthStats> {
  const row = await db
    .prepare(
      `SELECT
          SUM(CASE WHEN status = 'online'  THEN 1 ELSE 0 END) AS online,
          SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) AS offline,
          SUM(CASE WHEN status = 'unknown' THEN 1 ELSE 0 END) AS unknown,
          MAX(checked_at) AS last_checked
         FROM channel_health`,
    )
    .first<{ online: number | null; offline: number | null; unknown: number | null; last_checked: number | null }>();
  const online = row?.online ?? 0;
  const offline = row?.offline ?? 0;
  const unknown = row?.unknown ?? 0;
  const checked = online + offline + unknown;
  return {
    online,
    offline,
    unknown,
    last_checked: row?.last_checked ?? 0,
    offline_ratio: checked > 0 ? Math.round((offline / checked) * 100) : 0,
  };
}

/**
 * Cron entry point. Runs a bounded sweep; never throws (a dead probe must not
 * take down the scheduler). The batch size is overridable via HEALTH_CHECK_BATCH.
 */
export async function runScheduledHealthCheck(env: Env): Promise<void> {
  const raw = Number(env.HEALTH_CHECK_BATCH);
  const limit = Number.isFinite(raw) && raw > 0 ? Math.min(raw, MAX_PROBES_PER_RUN) : DEFAULT_HEALTH_BATCH;
  try {
    const summary = await healthCheckBatch(env, limit);
    logEvent('cron', '/health', 'HEALTH_CHECK', JSON.stringify(summary));
  } catch (err) {
    logEvent('cron', '/health', 'HEALTH_CHECK_FAILED', err instanceof Error ? err.message : 'unknown');
  }
}
