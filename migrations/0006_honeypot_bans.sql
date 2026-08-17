-- Durable, privacy-preserving IP bans raised by honeypots/login throttling.
-- Client addresses in these ban/counter tables are HMACed with SECRET_KEY;
-- raw IPs are never written to these tables. Migration 0007 separately adds
-- the operator-requested, retention-limited raw-IP authentication audit.
-- Migration number: 0006

CREATE TABLE IF NOT EXISTS security_bans (
  ip_hash    TEXT PRIMARY KEY,
  reason     TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  hit_count  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_security_bans_expires ON security_bans(expires_at);

-- Brute-force windows are durable so rotating Cloudflare colos cannot reset a
-- login attacker's counter. The same HMAC identifier is used; no raw IP is
-- retained here either.
CREATE TABLE IF NOT EXISTS security_login_failures (
  ip_hash        TEXT PRIMARY KEY,
  window_started INTEGER NOT NULL,
  last_failed    INTEGER NOT NULL,
  failure_count  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_security_login_failures_last ON security_login_failures(last_failed);
