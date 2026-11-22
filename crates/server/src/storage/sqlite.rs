use std::{
    collections::HashSet,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use subtle::ConstantTimeEq;
use tightlip_core::{
    Secret32, labels,
    share::{ShareId, Verifier, verify_access, verify_owner},
};

use super::{
    Blob, BlobKey, Blobs, Error, Evaluate, FileInfo, Hash, Metadata, Opened, Pending, Result,
    ShareInfo, Upload, UploadTarget,
};

const LIVE: &str = "id = ?1 AND expires_at > ?2 AND pending_until IS NULL
                    AND views_left > 0 AND attempts_left > 0";
const GRANT_SECONDS: i64 = 600;
const DUMMY_HASH: Hash = [0; 32];

pub(crate) struct Sqlite(Mutex<Connection>);

impl Sqlite {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(include_str!("schema.sql"))?;
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

impl Metadata for Sqlite {
    fn create(&self, pending: &Pending) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO shares(id, expires_at, pending_until, has_password, views_left,
                                attempts_left, upload_hash, wrapped_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                pending.id,
                pending.expires_at,
                pending.pending_until,
                pending.has_password,
                pending.views,
                pending.attempts,
                pending.upload_hash,
                pending.wrapped_key
            ],
        )?;
        Ok(())
    }

    fn check_pending_upload(&self, id: &ShareId, now: i64, hash: Option<&Hash>) -> Result<()> {
        let conn = self.connection()?;
        pending_auth(&conn, id, now, hash).map(|_| ())
    }

    fn upload_limit(&self, upload: &Upload, now: i64) -> Result<u64> {
        let conn = self.connection()?;
        upload_limit(&conn, upload, now)
    }

    fn put_manifest(&self, upload: &Upload, now: i64, contents: &[u8]) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if contents.len() as u64 > upload_limit(&tx, upload, now)? {
            return Err(Error::TooLarge);
        }
        tx.execute(
            "UPDATE shares SET manifest = ?2 WHERE id = ?1",
            params![upload.id, contents],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn put_file(
        &self,
        upload: &Upload,
        now: i64,
        blob: &Blob,
        publish: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let UploadTarget::File(n) = upload.target else {
            return Err(Error::Internal);
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if blob.size > upload_limit(&tx, upload, now)? {
            return Err(Error::TooLarge);
        }
        tx.execute(
            "INSERT INTO blob_garbage SELECT blob_key FROM files WHERE share_id = ?1 AND n = ?2",
            params![upload.id, n],
        )?;
        tx.execute(
            "INSERT INTO files(share_id, n, blob_key, size) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(share_id, n) DO UPDATE SET blob_key = excluded.blob_key, size = excluded.size",
            params![upload.id, n, blob.key, blob.size],
        )?;
        publish()?;
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

    fn info(&self, id: &ShareId, now: i64) -> Result<ShareInfo> {
        let info = self
            .connection()?
            .query_row(
                &format!("SELECT has_password, expires_at, views_left FROM shares WHERE {LIVE}"),
                params![id, now],
                |row| {
                    Ok(ShareInfo {
                        suite: labels::SUITE,
                        has_password: row.get(0)?,
                        expires_at: row.get(1)?,
                        views_left: row.get(2)?,
                    })
                },
            )
            .optional()?;
        info.ok_or(Error::Missing)
    }

    fn eval(&self, id: &ShareId, now: i64, evaluate: Box<Evaluate<'_>>) -> Result<([u8; 32], u32)> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let wrapped: Option<Vec<u8>> = tx
            .query_row(
                &format!("SELECT wrapped_key FROM shares WHERE {LIVE}"),
                params![id, now],
                |row| row.get(0),
            )
            .optional()?;
        let evaluated = evaluate(wrapped.as_deref());
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
        if wrapped.is_none() {
            return Err(Error::Missing);
        }
        let evaluated = evaluated?;
        let attempts = attempts.ok_or(Error::Missing)?;
        if attempts == 0 {
            destroy(&tx, id)?;
        }
        tx.commit()?;
        if attempts == 0 {
            checkpoint(&conn);
        }
        Ok((evaluated, attempts))
    }

    fn open(&self, id: &ShareId, now: i64, tag: Result<Secret32>, grant: &Hash) -> Result<Opened> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let verifier: Option<Verifier> = tx
            .query_row(
                &format!("SELECT access_verifier FROM shares WHERE {LIVE}"),
                params![id, now],
                |row| row.get(0),
            )
            .optional()?;
        let dummy = Secret32::from_bytes([0; 32]);
        let matches = verify_access(
            tag.as_ref().unwrap_or(&dummy),
            verifier.as_ref().unwrap_or(&DUMMY_HASH),
        );
        let authorized = matches && tag.is_ok() && verifier.is_some();
        let manifest: Option<Vec<u8>> = tx
            .query_row(
                "SELECT manifest FROM shares WHERE id = ?1 AND ?2",
                params![id, authorized],
                |row| row.get(0),
            )
            .optional()?;
        // SQLite evaluates the assignment expressions against the old row.
        let views: Option<u32> = tx
            .query_row(
                &format!(
                    "UPDATE shares SET views_left = views_left - 1,
                         wrapped_key = CASE WHEN views_left = 1 THEN NULL ELSE wrapped_key END,
                         manifest = CASE WHEN views_left = 1 THEN NULL ELSE manifest END
                      WHERE {LIVE} AND ?3 RETURNING views_left"
                ),
                params![id, now, authorized],
                |row| row.get(0),
            )
            .optional()?;
        if verifier.is_none() {
            return Err(Error::Missing);
        }
        let _ = tag?;
        if !matches {
            return Err(Error::Unauthorized);
        }
        let views = views.ok_or(Error::Missing)?;
        let manifest = manifest.ok_or(Error::Internal)?;
        let files = {
            let mut statement =
                tx.prepare("SELECT n, size FROM files WHERE share_id = ?1 ORDER BY n")?;
            statement
                .query_map(params![id], |row| {
                    Ok(FileInfo {
                        n: row.get(0)?,
                        size: row.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute(
            "INSERT INTO grants(hash, share_id, expires_at) VALUES (?1, ?2, ?3)",
            params![grant, id, now.saturating_add(GRANT_SECONDS)],
        )?;
        tx.commit()?;
        if views == 0 {
            checkpoint(&conn);
        }
        Ok(Opened { manifest, files })
    }

    fn file(&self, id: &ShareId, now: i64, n: u32, grant: Option<&Hash>) -> Result<Blob> {
        let presented = grant.unwrap_or(&DUMMY_HASH);
        // The truncated digest routes the lookup. The full digest authenticates.
        let found: Option<(Option<Hash>, Option<Blob>, bool)> = self
            .connection()?
            .query_row(
                "SELECT g.hash, f.blob_key, f.size, s.views_left > 0 AND s.attempts_left > 0
                 FROM shares s
                 LEFT JOIN grants g ON g.share_id = s.id
                    AND g.expires_at > ?2 AND substr(g.hash, 1, 16) = ?4
                 LEFT JOIN files f ON f.share_id = s.id AND f.n = ?3
                 WHERE s.id = ?1 AND s.expires_at > ?2 AND s.pending_until IS NULL",
                params![id, now, n, &presented[..16]],
                |row| {
                    let key: Option<BlobKey> = row.get(1)?;
                    let size: Option<u64> = row.get(2)?;
                    let blob = key.zip(size).map(|(key, size)| Blob { key, size });
                    Ok((row.get(0)?, blob, row.get(3)?))
                },
            )
            .optional()?;
        let expected = found.as_ref().and_then(|(hash, _, _)| hash.as_ref());
        let matches = bool::from(presented.ct_eq(expected.unwrap_or(&DUMMY_HASH)));
        let authenticated = matches && grant.is_some() && expected.is_some();
        let (_, blob, live) = found.ok_or(Error::Missing)?;
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
                        SELECT 1 FROM grants WHERE share_id = shares.id))",
            )?;
            statement
                .query_map(params![now], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<ShareId>>>()?
        };
        for id in doomed {
            destroy(&tx, &id)?;
        }
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
            |row| Ok((row.get(0)?, row.get(1)?)),
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

fn upload_limit(conn: &Connection, upload: &Upload, now: i64) -> Result<u64> {
    let pending = pending_auth(conn, &upload.id, now, upload.hash.as_ref())?;
    match upload.target {
        UploadTarget::Manifest => {
            let file_bytes: u64 = conn.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE share_id = ?1",
                params![upload.id],
                |row| row.get(0),
            )?;
            Ok(upload
                .manifest_cap
                .min(upload.total_cap.saturating_sub(file_bytes)))
        }
        UploadTarget::File(n) => {
            if n >= upload.file_cap {
                return Err(Error::TooLarge);
            }
            let (count, other_bytes): (u32, u64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN n != ?2 THEN size ELSE 0 END), 0)
                 FROM files WHERE share_id = ?1",
                params![upload.id, n],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if n > count {
                return Err(Error::FileGap);
            }
            Ok(upload
                .total_cap
                .saturating_sub(other_bytes.saturating_add(pending.manifest_size)))
        }
    }
}

fn destroy(tx: &Transaction<'_>, id: &ShareId) -> Result<()> {
    tx.execute(
        "UPDATE shares SET wrapped_key = NULL, manifest = NULL WHERE id = ?1",
        params![id],
    )?;
    tx.execute(
        "INSERT INTO blob_garbage SELECT blob_key FROM files WHERE share_id = ?1",
        params![id],
    )?;
    tx.execute("DELETE FROM shares WHERE id = ?1", params![id])?;
    Ok(())
}

fn checkpoint(conn: &Connection) {
    // secure_delete overwrites cells. Truncate the WAL to discard old frames too.
    // A busy reader can defer the checkpoint until the next sweep.
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}
