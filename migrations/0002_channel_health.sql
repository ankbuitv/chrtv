-- CHRTV channel health (proactive offline detection)
-- Migration number: 0002
--
-- The proxy already logs failures reactively (stream_failures) when a viewer
-- tunes in and the upstream is dead. That misses every channel nobody has
-- watched yet, so broken links silently stay "active" in the playlist.
-- This table holds the LATEST probed health state per channel, written by the
-- periodic health-check sweep, so the admin API can answer "which channels are
-- offline right now?".

CREATE TABLE IF NOT EXISTS channel_health (
  channel_id  TEXT PRIMARY KEY,            -- references channels(id); channels are deactivated, not deleted
  status      TEXT NOT NULL,               -- 'online' | 'offline' | 'unknown'
  error_code  TEXT NOT NULL DEFAULT '',    -- '' when online; otherwise an ErrorCodes value
  http_status INTEGER NOT NULL DEFAULT 0,  -- last upstream HTTP status (0 = no response)
  checked_at  INTEGER NOT NULL DEFAULT 0   -- unix seconds of the last probe; 0 = never checked
);
CREATE INDEX IF NOT EXISTS idx_channel_health_status  ON channel_health(status);
CREATE INDEX IF NOT EXISTS idx_channel_health_checked ON channel_health(checked_at);
