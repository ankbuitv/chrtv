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
 * `offline` is reserved for links that genuinely CANNOT BE REACHED — and only
 * after OFFLINE_CONFIRMATIONS consecutive probes agree:
 *  - the host is unreachable (connection refused / DNS dead);
 *  - the upstream stays silent past the 30s probe timeout;
 *  - 404/410 — the link itself is gone.
 * Everything else means the link IS reachable, so it is `unknown`, never
 * `offline`:
 *  - 5xx: the server answered — it is having a moment, not a dead link;
 *  - 200 + non-HLS body: reachable, just serving something odd (often an
 *    anti-bot interstitial shown to the probe while real players stream fine);
 *  - ports the Worker cannot open a subrequest to (e.g. :30113) cannot be
 *    probed here, so they remain unknown; strict origin hiding also prevents
 *    client redirects until the source is moved behind a fetchable relay;
 *  - 401/403/429/451 (auth / geo-block / rate-limit) depend on WHERE the probe
 *    runs. Cron triggers fire on an arbitrary Cloudflare colo, possibly
 *    outside the audience's country, so a 403 seen by the sweep proves nothing
 *    about what viewers see. Flagging those offline is how a healthy playlist
 *    ends up "fully offline".
 * A single unreachable probe can still be a network blip at the probing colo,
 * so the sweep keeps a per-channel `fail_streak`: the first unreachable result
 * records `unknown` (streak 1), and only a second consecutive one flips the
 * channel to `offline`. Any success or inconclusive probe resets the streak.
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

/**
 * A probe only counts as timed out after **30s of silence** — same bar the
 * proxy uses. Slow relays (devda.undo.it → real CDN, 10-25s TTFB, possibly
 * several redirect hops) load slowly but play fine; with a 6s timeout the
 * sweep flagged those healthy channels `offline` on every rotation even
 * though viewers watched them without any problem. The timeout applies per
 * fetch (each redirect hop), so the whole redirect chain is given the same
 * grace a real player would get.
 */
const PROBE_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 3;
const PROBE_PREFIX_BYTES = 64 * 1024;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Consecutive "unreachable" probes required before a channel is flagged
 * offline. One failed probe can be a network blip at whichever Cloudflare
 * colo the cron happened to run on; requiring a second consecutive failure
 * (next rotation, likely a different moment/colo) keeps healthy channels from
 * flickering offline. The first failure is stored as `unknown` with the
 * error code preserved, so the admin can still see it is suspect.
 */
export const OFFLINE_CONFIRMATIONS = 2;

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
/**
 * All probes fire in a single wave (concurrency = batch size). With a 30s
 * per-probe timeout, stacking waves (e.g. 8+4) would push a sweep full of dead
 * upstreams to ~60s wall clock — past the cron trigger limit on the Free plan —
 * and every result would be lost. One wave keeps the worst case at roughly one
 * probe duration; upstreams are all distinct hosts, so 12 concurrent probes
 * stay gentle.
 */
const PROBE_CONCURRENCY = MAX_PROBES_PER_RUN;
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
 * Reuses the proxy's SSRF + port-safety checks at every hop and follows
 * redirects manually inside ONE shared 30s budget (not 30s per hop).
 *
 * The returned `offline` is the RAW per-probe verdict "this link could not be
 * reached at all": host unreachable, silent past the timeout, or 404/410.
 * Anything the probe could reach — 5xx, auth/geo blocks, even a 200 whose
 * body is not HLS (often an anti-bot page shown only to the probe) — is
 * `unknown`, because the link itself IS accessible. The sweep additionally
 * requires OFFLINE_CONFIRMATIONS consecutive raw-offline probes before a
 * channel is actually persisted as offline.
 */
export async function probeChannel(url: string): Promise<ProbeResult> {
  if (!isSafeUpstreamUrl(url)) return { status: 'unknown', errorCode: ErrorCodes.UNSAFE_URL, httpStatus: 0 };
  if (!isFetchablePort(url)) return { status: 'unknown', errorCode: ErrorCodes.UNSUPPORTED_PORT, httpStatus: 0 };

  // One shared wall-clock budget for the WHOLE redirect chain. Per-hop
  // timeouts let a malicious/broken chain stretch a single probe to
  // hops × 30s, starving the rest of the sweep.
  const deadline = Date.now() + PROBE_TIMEOUT_MS;
  let currentUrl = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isSafeUpstreamUrl(currentUrl) || !isFetchablePort(currentUrl)) {
      return { status: 'unknown', errorCode: ErrorCodes.UNSUPPORTED_PORT, httpStatus: 0 };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_TIMEOUT, httpStatus: 0 };
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
        signal: AbortSignal.timeout(remaining),
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
        // The server answered (with a broken/looping redirect) — reachable,
        // just misbehaving. Not proof the link is dead.
        return { status: 'unknown', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: res.status };
      }
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return { status: 'unknown', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: res.status };
      }
      continue;
    }

    // A response arrived => the link IS reachable. From here only 404/410
    // ("this link no longer exists") still counts as a dead link; every
    // other answer — 5xx hiccup, auth/geo block, rate limit — is `unknown`.
    if (res.status === 404 || res.status === 410) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 'offline', errorCode: ErrorCodes.UPSTREAM_404, httpStatus: res.status };
    }
    if (!res.ok && res.status !== 206) {
      // 5xx / 401/403/429/451… — the server responded, so the link is not
      // dead. 5xx self-corrects (restart/overload); the 4xx family depends on
      // WHERE the probe runs. Report as unknown, keep the code for the admin.
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 'unknown', errorCode: classifyUpstreamStatus(res.status), httpStatus: res.status };
    }

    const prefix = await readPrefix(res, PROBE_PREFIX_BYTES);
    // 200 + non-HLS body: reachable but serving something odd — frequently an
    // anti-bot/interstitial page that only the datacenter probe sees while
    // real players stream fine. Suspicious, but NOT "link unreachable".
    return looksLikeHls(prefix)
      ? { status: 'online', errorCode: '', httpStatus: res.status }
      : { status: 'unknown', errorCode: ErrorCodes.INVALID_HLS, httpStatus: res.status };
  }
  return { status: 'unknown', errorCode: ErrorCodes.UPSTREAM_UNREACHABLE, httpStatus: 0 };
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
      `SELECT c.id, c.url, COALESCE(h.fail_streak, 0) AS fail_streak
         FROM channels c
         LEFT JOIN channel_health h ON h.channel_id = c.id
        WHERE c.active = 1 AND c.url != ''
        ORDER BY h.checked_at ASC, c.position ASC
        LIMIT ?`,
    )
    .bind(cap)
    .all<{ id: string; url: string; fail_streak: number }>();

  const now = Math.floor(Date.now() / 1000);
  const probed = await mapWithConcurrency(results, PROBE_CONCURRENCY, async (ch) => {
    const raw = await probeChannel(ch.url);
    // Confirmation gate: a channel only goes `offline` after
    // OFFLINE_CONFIRMATIONS consecutive unreachable probes. The first failed
    // probe is persisted as `unknown` (with the error code kept for the
    // admin) so one bad network moment never flags a watchable channel.
    const streak = raw.status === 'offline' ? (ch.fail_streak ?? 0) + 1 : 0;
    const status: HealthStatus = raw.status === 'offline' && streak < OFFLINE_CONFIRMATIONS ? 'unknown' : raw.status;
    const r = { id: ch.id, status, errorCode: raw.errorCode, httpStatus: raw.httpStatus, streak };
    // Persist each result the moment it lands instead of one batch write at
    // the end: with a 30s probe timeout, a sweep full of dead upstreams can
    // brush against the cron wall-clock limit, and a final write would lose
    // every finished probe — leaving the same slow channels "oldest checked"
    // forever, hogging every future sweep.
    try {
      await env.DB
        .prepare(
          `INSERT INTO channel_health (channel_id, status, error_code, http_status, checked_at, fail_streak)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(channel_id) DO UPDATE SET
             status = excluded.status,
             error_code = excluded.error_code,
             http_status = excluded.http_status,
             checked_at = excluded.checked_at,
             fail_streak = excluded.fail_streak`,
        )
        .bind(r.id, r.status, r.errorCode, r.httpStatus, now, r.streak)
        .run();
    } catch {
      /* health persistence must never break the sweep — next rotation retries */
    }
    return r;
  });

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
