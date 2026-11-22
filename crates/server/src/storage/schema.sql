CREATE TABLE IF NOT EXISTS shares (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    expires_at INTEGER NOT NULL,
    pending_until INTEGER,
    has_password INTEGER NOT NULL,
    views_left INTEGER NOT NULL CHECK (views_left >= 0),
    attempts_left INTEGER NOT NULL CHECK (attempts_left >= 0),
    upload_hash BLOB,
    wrapped_key BLOB,
    manifest BLOB,
    access_verifier BLOB,
    owner_verifier BLOB
) STRICT;
CREATE INDEX IF NOT EXISTS shares_expiry ON shares(expires_at);
CREATE INDEX IF NOT EXISTS shares_pending ON shares(pending_until);

CREATE TABLE IF NOT EXISTS files (
    share_id BLOB NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    n INTEGER NOT NULL,
    blob_key BLOB NOT NULL UNIQUE CHECK (length(blob_key) = 16),
    size INTEGER NOT NULL,
    PRIMARY KEY (share_id, n)
) STRICT;

CREATE TABLE IF NOT EXISTS grants (
    hash BLOB NOT NULL PRIMARY KEY CHECK (length(hash) = 32),
    share_id BLOB NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS grants_expiry ON grants(expires_at);
CREATE INDEX IF NOT EXISTS grants_share ON grants(share_id);
CREATE UNIQUE INDEX IF NOT EXISTS grants_lookup ON grants(substr(hash, 1, 16));

CREATE TABLE IF NOT EXISTS blob_garbage (
    blob_key BLOB NOT NULL PRIMARY KEY CHECK (length(blob_key) = 16)
) STRICT;
