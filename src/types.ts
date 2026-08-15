/** CHRTV worker environment bindings. */
export interface Env {
  DB: D1Database;
  /** Raw GitHub URL of the M3U playlist (source of truth, lives in this repo). */
  PLAYLIST_URL: string;
  /** Optional upstream XMLTV EPG URL. Empty => minimal generated XMLTV. */
  EPG_URL: string;
  /** "true" => /tv.m3u works without an access key. */
  PUBLIC_PLAYLIST: string;
  /**
   * Optional fallback HLS playlist served when a channel upstream is dead.
   * Comma-separated list allowed; candidates are tried in order.
   * A candidate on a Workers-fetchable port is fetched + re-proxied (segments
   * become /seg/{token}); one on a port Workers cannot open (e.g. :30113) is
   * served to the player as a 302 redirect so it still plays.
   * Empty => the empty "signal lost" error manifest is served.
   */
  FALLBACK_M3U_URL?: string;
  /** Secret used for token encryption + credential hashing. Set via wrangler secret. */
  SECRET_KEY: string;
  /** Bearer token for the admin API. Admin API is disabled when unset. */
  ADMIN_TOKEN?: string;
  /**
   * How many channels the periodic health-check sweep probes per cron tick.
   * Defaults to 20; capped at MAX_PROBES_PER_RUN. Larger = faster full sweep,
   * at the cost of more upstream subrequests per invocation.
   */
  HEALTH_CHECK_BATCH?: string;
  /** Test-only: D1 migrations injected by vitest-pool-workers. */
  TEST_MIGRATIONS?: unknown;
}

export interface ChannelRow {
  id: string;
  xtream_id: number;
  name: string;
  url: string;
  tvg_id: string;
  tvg_logo: string;
  category_id: number | null;
  category_name?: string | null;
  position: number;
  active: number;
}

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  password_salt: string;
  status: string;
  max_connections: number;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface AccessKeyRow {
  id: number;
  key_hash: string;
  key_prefix: string;
  label: string;
  username: string;
  status: string;
  max_devices: number;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export type RequestContext = {
  requestId: string;
};
