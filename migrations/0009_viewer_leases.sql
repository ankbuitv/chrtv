-- Rolling viewer playlist leases.
-- One opaque generation is kept while an identity is actively requesting live
-- manifests. After 60 seconds without a manifest request, the old generation
-- is invalidated and the next playlist fetch receives fresh channel URLs.

CREATE TABLE IF NOT EXISTS viewer_leases (
  identity_hash TEXT PRIMARY KEY,
  lease_id      TEXT NOT NULL UNIQUE,
  issued_at     INTEGER NOT NULL,
  activated_at INTEGER,
  last_seen     INTEGER NOT NULL DEFAULT 0,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_viewer_leases_seen ON viewer_leases(last_seen);
CREATE INDEX IF NOT EXISTS idx_viewer_leases_updated ON viewer_leases(updated_at);
