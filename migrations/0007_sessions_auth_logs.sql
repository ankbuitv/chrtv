-- Revocable user playlist sessions and authentication audit history.
-- Migration number: 0007
--
-- Session bearer tokens are returned once and only their HMAC is persisted.
-- Login IPs are intentionally stored in plaintext at the operator's request;
-- auth_events is retention-limited by the daily cleanup job.

CREATE TABLE IF NOT EXISTS user_sessions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  token_hash   TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  device_name  TEXT NOT NULL DEFAULT '',
  user_agent   TEXT NOT NULL DEFAULT '',
  ip_address   TEXT NOT NULL DEFAULT '',
  last_ip      TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'active', -- active|revoked|expired
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  expires_at   INTEGER                         -- follows users.expires_at; NULL = until revoked
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen ON user_sessions(last_seen);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

CREATE TABLE IF NOT EXISTS auth_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER REFERENCES users(id),
  session_id  INTEGER,
  username    TEXT NOT NULL DEFAULT '',
  event_type  TEXT NOT NULL, -- login|playlist|xtream|access_key
  route       TEXT NOT NULL,
  outcome     TEXT NOT NULL, -- success|failure|blocked|limit
  ip_address  TEXT NOT NULL DEFAULT '',
  user_agent  TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_events_created ON auth_events(created_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip ON auth_events(ip_address, created_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_outcome ON auth_events(outcome, created_at);
