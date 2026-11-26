use std::{
    collections::HashSet,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use subtle::ConstantTimeEq;
use tightlip_core::{
    Secret32, labels,
    share::{self, ShareId, Verifier, verify_access, verify_eval, verify_owner},
};

use super::{
    Blob, BlobKey, Blobs, Error, Evaluate, FileInfo, Hash, Metadata, OpenRequest, Opened, Pending,
    Result, ShareInfo, Upload, UploadTarget,
};

const LIVE: &str = "id = ?1 AND expires_at > ?2 AND pending_until IS NULL
                    AND views_left > 0 AND attempts_left > 0";
const OPENABLE: &str = "id = ?1 AND expires_at > ?2 AND pending_until IS NULL
                        AND views_left > 0 AND (final_attempt_until IS NULL OR final_attempt_until > ?2)";
const FINAL_ATTEMPT_SECONDS: i64 = 120;
const GRANT_SECONDS: i64 = 600;
const STORAGE_FULL: Error = Error::RateLimited { retry_after: 600 };
const DUMMY_HASH: Hash = [0; 32];
const SCHEMA_VERSION: u32 = 2;

pub(crate) struct Sqlite(Mutex<Connection>);

impl Sqlite {
    pub fn open(
        path: &Path,
        now: i64,
        current: &Secret32,
        current_id: u32,
        previous: Option<&(u32, Secret32)>,
    ) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version = tx.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::Internal);
        }
        let shares_exist: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'shares')",
            [],
            |row| row.get(0),
        )?;
        let migrate = version == 0 && shares_exist;
        if migrate {
            tx.execute_batch(
                "ALTER TABLE files RENAME TO old_files;
                 ALTER TABLE grants RENAME TO old_grants;
                 DROP INDEX grants_expiry;
                 DROP INDEX grants_share;
                 DROP INDEX grants_lookup;
                 ALTER TABLE shares ADD COLUMN final_attempt_until INTEGER;
                 ALTER TABLE blob_garbage ADD COLUMN size INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        tx.execute_batch(include_str!("schema.sql"))?;
        if migrate {
            tx.execute_batch(
                "INSERT INTO files SELECT * FROM old_files;
                 INSERT INTO grants
                     SELECT g.hash, g.share_id, MIN(g.expires_at, s.expires_at)
                     FROM old_grants g JOIN shares s ON s.id = g.share_id;
                 DROP TABLE old_files;
                 DROP TABLE old_grants;",
            )?;
        }
        if version == 0 {
            tx.execute_batch(include_str!("accounting.sql"))?;
        }
        if version < SCHEMA_VERSION {
            if shares_exist {
                tx.execute_batch(
                    "ALTER TABLE shares ADD COLUMN eval_verifier BLOB
                         CHECK (length(eval_verifier) = 32);",
                )?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        rewrap_keys(&tx, now, current, current_id, previous)?;
        tx.commit()?;
        Ok(Self(Mutex::new(conn)))
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.0.lock().map_err(|_| Error::Internal)
    }

    pub fn live_blobs(&self) -> Result<HashSet<BlobKey>> {
        let conn = self.connection()?;
        let mut statement = conn.prepare("SELECT blob_key FROM files")?;
        Ok(statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?)
    }
}

fn rewrap_keys(
    tx: &Transaction<'_>,
    now: i64,
    current: &Secret32,
    current_id: u32,
    previous: Option<&(u32, Secret32)>,
) -> Result<()> {
    let ids = {
        let mut statement = tx.prepare(
            "SELECT id FROM shares WHERE wrapped_key IS NOT NULL AND expires_at > ?1
               AND (pending_until IS NULL OR pending_until > ?1)",
        )?;
        statement
            .query_map(params![now], |row| row.get::<_, ShareId>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut read = tx.prepare("SELECT wrapped_key FROM shares WHERE id = ?1")?;
    let mut write = tx.prepare("UPDATE shares SET wrapped_key = ?2 WHERE id = ?1")?;
    for id in ids {
        let wrapped: Vec<u8> = read.query_row(params![id], |row| row.get(0))?;
        let stored_id = share::wrapped_kek_id(&wrapped).map_err(|_| Error::KeyRotation)?;
        let kek = match previous {
            _ if stored_id == current_id => current,
            Some((previous_id, key)) if stored_id == *previous_id => key,
            None if stored_id == 0 => current,
            _ => return Err(Error::KeyRotation),
        };
        let key = share::unwrap_oprf_key(kek, stored_id, &id, &wrapped)
            .map_err(|_| Error::KeyRotation)?;
        if stored_id != current_id {
            let wrapped = share::wrap_oprf_key(current, current_id, &id, &key)
                .map_err(|_| Error::KeyRotation)?;
            write.execute(params![id, wrapped])?;
        }
    }
    Ok(())
}

impl Metadata for Sqlite {
    fn check_storage(&self, storage_cap: u64) -> Result<()> {
        let conn = self.connection()?;
        check_storage(&conn, storage_cap)
    }

    fn create(&self, pending: &Pending, storage_cap: u64) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_storage(&tx, storage_cap)?;
        let created = tx.execute(
            "INSERT INTO shares(id, expires_at, pending_until, has_password, views_left,
                                attempts_left, upload_hash, wrapped_key, eval_verifier)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
             WHERE NOT EXISTS (SELECT 1 FROM grants WHERE share_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM files WHERE share_id = ?1)",
            params![
                pending.id,
                pending.expires_at,
                pending.pending_until,
                pending.has_password,
                pending.views,
                pending.attempts,
                pending.upload_hash,
                pending.wrapped_key,
                pending.eval_verifier
            ],
        )?;
        if created == 0 {
            return Err(Error::Internal);
        }
        tx.commit()?;
        Ok(())
    }

    fn check_pending_upload(&self, id: &ShareId, now: i64, hash: Option<&Hash>) -> Result<()> {
        let conn = self.connection()?;
        pending_auth(&conn, id, now, hash).map(|_| ())
    }

    fn upload_limit(&self, upload: &Upload, now: i64) -> Result<u64> {
        let conn = self.connection()?;
        let (cap, used) = upload_space(&conn, upload, now)?;
        if used >= upload.storage_cap {
            return Err(STORAGE_FULL);
        }
        Ok(cap)
    }

    fn put_manifest(&self, upload: &Upload, now: i64, contents: &[u8]) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (cap, used) = upload_space(&tx, upload, now)?;
        if contents.len() as u64 > cap {
            return Err(Error::TooLarge);
        }
        if used.saturating_add(contents.len() as u64) > upload.storage_cap {
            return Err(STORAGE_FULL);
        }
        tx.execute(
            "UPDATE shares SET manifest = ?2 WHERE id = ?1",
            params![upload.id, contents],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn put_file(&self, upload: &Upload, now: i64, blob: &Blob) -> Result<()> {
        let UploadTarget::File(n) = upload.target else {
            return Err(Error::Internal);
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (cap, used) = upload_space(&tx, upload, now)?;
        if blob.size > cap {
            return Err(Error::TooLarge);
        }
        if used.saturating_add(blob.size) > upload.storage_cap {
            return Err(STORAGE_FULL);
        }
        let size = i64::try_from(blob.size).map_err(|_| Error::TooLarge)?;
        tx.execute(
            "INSERT INTO files(share_id, n, blob_key, size) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(share_id, n) DO UPDATE SET blob_key = excluded.blob_key, size = excluded.size",
            params![upload.id, n, blob.key, size],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn commit(
        &self,
        id: &ShareId,
        now: i64,
        upload_hash: Option<&Hash>,
        verifiers: Result<(Verifier, Verifier)>,
    ) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending = pending_auth(&tx, id, now, upload_hash)?;
        let (access, owner) = verifiers?;
        if pending.manifest_size == 0 {
            return Err(Error::Invalid);
        }
        tx.execute(
            "UPDATE shares SET pending_until = NULL, upload_hash = NULL,
                               access_verifier = ?2, owner_verifier = ?3 WHERE id = ?1",
            params![id, access, owner],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn info(&self, id: &ShareId, now: i64, tag: Option<&Secret32>) -> Result<ShareInfo> {
        let info = self
            .connection()?
            .query_row(
                &format!(
                    "SELECT has_password, expires_at, views_left, eval_verifier
                          FROM shares WHERE {LIVE}"
                ),
                params![id, now],
                |row| {
                    Ok((
                        ShareInfo {
                            suite: labels::SUITE,
                            has_password: row.get(0)?,
                            expires_at: row.get(1)?,
                            views_left: row.get(2)?,
                        },
                        row.get::<_, Option<Verifier>>(3)?,
                    ))
                },
            )
            .optional()?;
        let authorized = eval_authorized(
            info.as_ref().and_then(|(_, verifier)| verifier.as_ref()),
            tag,
        );
        let (info, _) = info.ok_or(Error::Missing)?;
        if !authorized {
            return Err(Error::Unauthorized);
        }
        Ok(info)
    }

    fn eval(
        &self,
        id: &ShareId,
        now: i64,
        tag: Result<Option<Secret32>>,
        evaluate: Box<Evaluate<'_>>,
    ) -> Result<([u8; 32], u32)> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(Vec<u8>, Option<Verifier>)> = tx
            .query_row(
                &format!("SELECT wrapped_key, eval_verifier FROM shares WHERE {LIVE}"),
                params![id, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let authorized = eval_authorized(
            row.as_ref().and_then(|(_, verifier)| verifier.as_ref()),
            tag.as_ref().ok().and_then(Option::as_ref),
        );
        let wrapped = row.as_ref().filter(|_| authorized && tag.is_ok());
        let evaluated = evaluate(wrapped.map(|(key, _)| key.as_slice()));
        let attempts: Option<u32> = tx
            .query_row(
                &format!(
                    "UPDATE shares SET attempts_left = attempts_left - 1
                      WHERE {LIVE} AND ?3 RETURNING attempts_left"
                ),
                params![id, now, wrapped.is_some() && evaluated.is_ok()],
                |row| row.get(0),
            )
            .optional()?;
        if row.is_none() {
            return Err(Error::Missing);
        }
        tag?;
        if !authorized {
            return Err(Error::Unauthorized);
        }
        let evaluated = evaluated?;
        let attempts = attempts.ok_or(Error::Missing)?;
        if attempts == 0 {
            tx.execute(
                "UPDATE shares SET wrapped_key = NULL, final_attempt_until = MIN(expires_at, ?2)
                 WHERE id = ?1",
                params![id, now.saturating_add(FINAL_ATTEMPT_SECONDS)],
            )?;
        }
        tx.commit()?;
        if attempts == 0 {
            checkpoint(&conn);
        }
        Ok((evaluated, attempts))
    }

    fn open(
        &self,
        id: &ShareId,
        now: i64,
        request: Result<OpenRequest>,
        grant: &Hash,
    ) -> Result<Opened> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_hash = request
            .as_ref()
            .map_or(&DUMMY_HASH, |body| &body.request_hash);
        let replay: Option<(u32, i64)> = tx
            .query_row(
                "SELECT views_left, expires_at FROM open_requests WHERE share_id = ?1 AND hash = ?2",
                params![id, request_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let state: Option<(Verifier, i64, bool)> = tx
            .query_row(
                "SELECT access_verifier, expires_at, views_left > 0
                     AND (final_attempt_until IS NULL OR final_attempt_until > ?2)
                 FROM shares WHERE id = ?1 AND expires_at > ?2 AND pending_until IS NULL",
                params![id, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let dummy = Secret32::from_bytes([0; 32]);
        let matches = verify_access(
            request.as_ref().map_or(&dummy, |body| &body.tag),
            state
                .as_ref()
                .map_or(&DUMMY_HASH, |(verifier, _, _)| verifier),
        );
        let (_, expires_at, openable) = state.ok_or(Error::Missing)?;
        if replay.is_some_and(|(_, until)| until <= now)
            || !(openable || (replay.is_some() && matches && request.is_ok()))
        {
            return Err(Error::Missing);
        }
        let request = request?;
        if !matches {
            return Err(Error::Unauthorized);
        }
        let (views_left, grant_until) = if let Some(snapshot) = replay {
            snapshot
        } else {
            let views_left: u32 = tx.query_row(
                &format!(
                    "UPDATE shares SET views_left = views_left - 1,
                         wrapped_key = CASE WHEN views_left = 1 THEN NULL ELSE wrapped_key END
                     WHERE {OPENABLE} RETURNING views_left"
                ),
                params![id, now],
                |row| row.get(0),
            )?;
            let grant_until = expires_at.min(now.saturating_add(GRANT_SECONDS));
            tx.execute(
                "INSERT INTO open_requests(share_id, hash, expires_at, views_left)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, request.request_hash, grant_until, views_left],
            )?;
            (views_left, grant_until)
        };
        let manifest = tx.query_row(
            "SELECT manifest FROM shares WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        let files = {
            let mut statement =
                tx.prepare("SELECT n, size FROM files WHERE share_id = ?1 ORDER BY n")?;
            statement
                .query_map(params![id], |row| {
                    Ok(FileInfo {
                        n: row.get(0)?,
                        size: read_size(row, 1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute(
            "INSERT INTO grants(hash, share_id, expires_at) VALUES (?1, ?2, ?3)",
            params![grant, id, grant_until],
        )?;
        tx.commit()?;
        if views_left == 0 && replay.is_none() {
            checkpoint(&conn);
        }
        Ok(Opened {
            manifest,
            files,
            views_left,
        })
    }

    fn file(&self, id: &ShareId, now: i64, n: u32, grant: Option<&Hash>) -> Result<Blob> {
        let presented = grant.unwrap_or(&DUMMY_HASH);
        // The truncated digest routes the lookup. The full digest authenticates.
        let (expected, blob, live): (Option<Hash>, Option<Blob>, bool) =
            self.connection()?.query_row(
                "SELECT g.hash, f.blob_key, f.size, COALESCE(s.views_left > 0 AND s.attempts_left > 0, 0)
                 FROM (SELECT ?1 AS id) requested
                 LEFT JOIN shares s ON s.id = requested.id
                    AND s.expires_at > ?2 AND s.pending_until IS NULL
                 LEFT JOIN grants g ON g.share_id = requested.id
                    AND g.expires_at > ?2 AND substr(g.hash, 1, 16) = ?4
                 LEFT JOIN files f ON f.share_id = requested.id AND f.n = ?3",
                params![id, now, n, &presented[..16]],
                |row| {
                    let key: Option<BlobKey> = row.get(1)?;
                    let blob = if let Some(key) = key {
                        Some(Blob { key, size: read_size(row, 2)? })
                    } else {
                        None
                    };
                    Ok((row.get(0)?, blob, row.get(3)?))
                },
            )?;
        let matches = bool::from(presented.ct_eq(expected.as_ref().unwrap_or(&DUMMY_HASH)));
        let authenticated = matches && grant.is_some() && expected.is_some();
        if !authenticated {
            return Err(if live {
                Error::Unauthorized
            } else {
                Error::Missing
            });
        }
        blob.ok_or(Error::Missing)
    }

    fn delete(&self, id: &ShareId, now: i64, owner: Option<&Secret32>) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let verifier: Option<Verifier> = tx
            .query_row(
                "SELECT owner_verifier FROM shares
             WHERE id = ?1 AND expires_at > ?2 AND pending_until IS NULL",
                params![id, now],
                |row| row.get(0),
            )
            .optional()?;
        let dummy = Secret32::from_bytes([0; 32]);
        let matches = verify_owner(
            owner.unwrap_or(&dummy),
            verifier.as_ref().unwrap_or(&DUMMY_HASH),
        );
        if verifier.is_none() {
            return Err(Error::Missing);
        }
        if !matches || owner.is_none() {
            return Err(Error::Unauthorized);
        }
        destroy(&tx, id)?;
        tx.execute(
            "DELETE FROM files WHERE share_id = ?1 AND NOT EXISTS (
                SELECT 1 FROM grants WHERE share_id = ?1 AND expires_at > ?2)",
            params![id, now],
        )?;
        tx.commit()?;
        checkpoint(&conn);
        Ok(())
    }

    fn sweep(&self, now: i64) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM grants WHERE expires_at <= ?1", params![now])?;
        let doomed = {
            let mut statement = tx.prepare(
                "SELECT id FROM shares
                 WHERE expires_at <= ?1 OR pending_until <= ?1
                    OR (views_left = 0 AND NOT EXISTS (
                        SELECT 1 FROM grants WHERE share_id = shares.id))
                    OR (final_attempt_until <= ?1 AND NOT EXISTS (
                        SELECT 1 FROM open_requests WHERE share_id = shares.id AND expires_at > ?1))",
            )?;
            statement
                .query_map(params![now], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<ShareId>>>()?
        };
        for id in doomed {
            destroy(&tx, &id)?;
        }
        tx.execute(
            "DELETE FROM files
             WHERE NOT EXISTS (SELECT 1 FROM shares WHERE id = files.share_id)
               AND NOT EXISTS (SELECT 1 FROM grants WHERE share_id = files.share_id)",
            [],
        )?;
        tx.commit()?;
        checkpoint(&conn);
        Ok(())
    }

    fn collect_garbage(&self, blobs: &dyn Blobs) -> Result<()> {
        let conn = self.connection()?;
        let mut statement = conn.prepare("SELECT blob_key FROM blob_garbage")?;
        let keys = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<BlobKey>>>()?;
        let mut result = Ok(());
        for key in keys {
            match blobs.remove(&key) {
                Ok(()) => {
                    conn.execute("DELETE FROM blob_garbage WHERE blob_key = ?1", params![key])?;
                }
                Err(error) => result = Err(error),
            }
        }
        result
    }
}

fn eval_authorized(expected: Option<&Verifier>, tag: Option<&Secret32>) -> bool {
    let dummy = Secret32::from_bytes([0; 32]);
    let matches = verify_eval(tag.unwrap_or(&dummy), expected.unwrap_or(&DUMMY_HASH));
    expected.is_none() || (matches && tag.is_some())
}

struct PendingAuth {
    manifest_size: u64,
}

fn pending_auth(
    conn: &Connection,
    id: &ShareId,
    now: i64,
    hash: Option<&Hash>,
) -> Result<PendingAuth> {
    let row: Option<(Hash, u64)> = conn
        .query_row(
            "SELECT upload_hash, COALESCE(length(manifest), 0) FROM shares
         WHERE id = ?1 AND expires_at > ?2 AND pending_until > ?2",
            params![id, now],
            |row| Ok((row.get(0)?, read_size(row, 1)?)),
        )
        .optional()?;
    let expected = row.as_ref().map_or(&DUMMY_HASH, |(expected, _)| expected);
    let matches = bool::from(hash.unwrap_or(&DUMMY_HASH).ct_eq(expected));
    let (_, manifest_size) = row.ok_or(Error::Missing)?;
    if !matches || hash.is_none() {
        return Err(Error::Unauthorized);
    }
    Ok(PendingAuth { manifest_size })
}

fn upload_space(conn: &Connection, upload: &Upload, now: i64) -> Result<(u64, u64)> {
    let pending = pending_auth(conn, &upload.id, now, upload.hash.as_ref())?;
    let used = storage_used(conn)?;
    match upload.target {
        UploadTarget::Manifest => {
            let file_bytes: u64 = conn.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE share_id = ?1",
                params![upload.id],
                |row| read_size(row, 0),
            )?;
            let cap = upload
                .manifest_cap
                .min(upload.total_cap.saturating_sub(file_bytes));
            Ok((cap, used.saturating_sub(pending.manifest_size)))
        }
        UploadTarget::File(n) => {
            if n >= upload.file_cap {
                return Err(Error::TooLarge);
            }
            let (count, other_bytes): (u32, u64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN n != ?2 THEN size ELSE 0 END), 0)
                 FROM files WHERE share_id = ?1",
                params![upload.id, n],
                |row| Ok((row.get(0)?, read_size(row, 1)?)),
            )?;
            if n > count {
                return Err(Error::FileGap);
            }
            let cap = upload
                .total_cap
                .saturating_sub(other_bytes.saturating_add(pending.manifest_size));
            Ok((cap, used))
        }
    }
}

fn destroy(tx: &Transaction<'_>, id: &ShareId) -> Result<()> {
    tx.execute(
        "UPDATE shares SET wrapped_key = NULL, manifest = NULL WHERE id = ?1",
        params![id],
    )?;
    tx.execute("DELETE FROM shares WHERE id = ?1", params![id])?;
    Ok(())
}

fn storage_used(conn: &Connection) -> Result<u64> {
    Ok(
        conn.query_row("SELECT bytes FROM storage_usage", [], |row| {
            read_size(row, 0)
        })?,
    )
}

fn read_size(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn check_storage(conn: &Connection, cap: u64) -> Result<()> {
    if storage_used(conn)? >= cap {
        return Err(STORAGE_FULL);
    }
    Ok(())
}

fn checkpoint(conn: &Connection) {
    // secure_delete overwrites cells. Truncate the WAL to discard old frames too.
    // A busy reader can defer the checkpoint until the next sweep.
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_blobs_and_caps_existing_grants_at_share_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite3");
        let conn = Connection::open(&path).unwrap();
        let legacy = include_str!("schema.sql")
            .replace(
                ",\n    eval_verifier BLOB CHECK (length(eval_verifier) = 32)",
                "",
            )
            .replace(",\n    final_attempt_until INTEGER", "")
            .replace(
                "share_id BLOB NOT NULL,",
                "share_id BLOB NOT NULL REFERENCES shares(id) ON DELETE CASCADE,",
            );
        let (tables, garbage) = legacy
            .split_once("CREATE TABLE IF NOT EXISTS open_requests")
            .unwrap();
        let (_, garbage) = garbage
            .split_once("CREATE TABLE IF NOT EXISTS blob_garbage")
            .unwrap();
        let garbage = garbage.replace(",\n    size INTEGER NOT NULL", "");
        conn.execute_batch(&format!(
            "{tables}CREATE TABLE IF NOT EXISTS blob_garbage{garbage}"
        ))
        .unwrap();

        let id = [1_u8; 16];
        let blob = [2_u8; 16];
        let grant = [3_u8; 32];
        conn.execute(
            "INSERT INTO shares(id, expires_at, has_password, views_left, attempts_left, manifest)
             VALUES (?1, 100, 0, 0, 1, x'010203')",
            params![id],
        )
        .unwrap();
        conn.execute("INSERT INTO files VALUES (?1, 0, ?2, 4)", params![id, blob])
            .unwrap();
        conn.execute(
            "INSERT INTO grants VALUES (?1, ?2, 660)",
            params![grant, id],
        )
        .unwrap();
        drop(conn);

        let kek = Secret32::generate().unwrap();
        let store = Sqlite::open(&path, 99, &kek, 1, None).unwrap();
        assert_eq!(storage_used(&store.connection().unwrap()).unwrap(), 7);
        assert_eq!(store.live_blobs().unwrap(), HashSet::from([blob]));
        assert_eq!(store.file(&id, 99, 0, Some(&grant)).unwrap().key, blob);
        assert!(matches!(
            store.file(&id, 100, 0, Some(&grant)),
            Err(Error::Missing)
        ));
        store.sweep(100).unwrap();
        assert!(store.live_blobs().unwrap().is_empty());
        assert_eq!(storage_used(&store.connection().unwrap()).unwrap(), 4);
    }
}
