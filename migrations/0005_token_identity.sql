-- Bind access keys to an optional D1 user so stream tokens can carry both the
-- access-key id and authenticated user id.
-- Migration number: 0005

ALTER TABLE access_keys ADD COLUMN user_id INTEGER REFERENCES users(id);
CREATE INDEX IF NOT EXISTS idx_access_keys_user ON access_keys(user_id);
