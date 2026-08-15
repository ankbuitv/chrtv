-- CHRTV initial schema
-- Migration number: 0001

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('sync_lock', ''),
  ('playlist_hash', ''),
  ('playlist_source', ''),
  ('epg_source', ''),
  ('last_sync', ''),
  ('sync_status', 'never'),
  ('channel_count', '0'),
  ('category_count', '0'),
  ('sync_seq', '0'),
  ('public_playlist', ''),
  ('playlist_token_ttl', '2592000');

CREATE TABLE IF NOT EXISTS categories (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  name     TEXT NOT NULL UNIQUE,
  position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS channels (
  id          TEXT PRIMARY KEY,          -- stable hash(url|name|tvg-id)
  xtream_id   INTEGER UNIQUE,            -- stable numeric id for Xtream clients
  name        TEXT NOT NULL,
  url         TEXT NOT NULL,
  tvg_id      TEXT NOT NULL DEFAULT '',
  tvg_logo    TEXT NOT NULL DEFAULT '',
  category_id INTEGER REFERENCES categories(id),
  position    INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1,
  sync_seq    INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_channels_active   ON channels(active, position);
CREATE INDEX IF NOT EXISTS idx_channels_category ON channels(category_id, active);
CREATE INDEX IF NOT EXISTS idx_channels_xtream   ON channels(xtream_id);

CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  username        TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,             -- HMAC-SHA256(SECRET_KEY, salt:password)
  password_salt   TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active', -- active|disabled|expired|revoked
  max_connections INTEGER NOT NULL DEFAULT 1,
  expires_at      INTEGER,                   -- unix seconds, NULL = never
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE TABLE IF NOT EXISTS access_keys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash    TEXT NOT NULL UNIQUE,          -- HMAC-SHA256(SECRET_KEY, key); raw key never stored
  key_prefix  TEXT NOT NULL,                 -- first chars for identification in admin UI
  label       TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',      -- optional owner label
  status      TEXT NOT NULL DEFAULT 'active', -- active|disabled|expired|revoked
  max_devices INTEGER NOT NULL DEFAULT 3,
  expires_at  INTEGER,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_keys_status ON access_keys(status);

CREATE TABLE IF NOT EXISTS devices (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  access_key_id INTEGER NOT NULL REFERENCES access_keys(id),
  mac_address   TEXT NOT NULL,               -- normalized AA:BB:CC:DD:EE:FF
  user_agent    TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'active', -- active|disabled|revoked
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  UNIQUE (access_key_id, mac_address)
);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_key ON devices(access_key_id, status);

CREATE TABLE IF NOT EXISTS sync_logs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at     INTEGER NOT NULL,
  finished_at    INTEGER,
  status         TEXT NOT NULL,              -- ok|skipped|failed|busy
  trigger_by     TEXT NOT NULL,              -- cron|admin
  channel_count  INTEGER NOT NULL DEFAULT 0,
  category_count INTEGER NOT NULL DEFAULT 0,
  playlist_hash  TEXT NOT NULL DEFAULT '',
  error          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sync_logs_started ON sync_logs(started_at);

CREATE TABLE IF NOT EXISTS stream_failures (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id TEXT NOT NULL,
  error_code TEXT NOT NULL,
  http_status INTEGER NOT NULL DEFAULT 0,
  detail     TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failures_channel ON stream_failures(channel_id, created_at);
CREATE INDEX IF NOT EXISTS idx_failures_created ON stream_failures(created_at);
