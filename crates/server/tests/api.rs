#![forbid(unsafe_code)]

use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;
use tightlip_core::{
    Secret32, b64, labels,
    manifest::{self, FileEntry, Manifest, VERSION},
    share::{self, ShareId, ShareKeys},
    stream::CHUNK_LEN,
};
use tightlip_server::{
    Clock, Server,
    config::{Config, Limits},
};
use tokio::task::JoinSet;
use tower::ServiceExt;
use zeroize::Zeroizing;

const START: i64 = 1_800_000_000;

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

struct Fixture {
    server: Server,
    clock: Arc<TestClock>,
    kek: Secret32,
    dir: TempDir,
}

impl Fixture {
    fn new(limits: Limits) -> Self {
        Self::with_proxy(limits, false)
    }

    fn with_proxy(limits: Limits, trust_proxy: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock(AtomicI64::new(START)));
        let kek = Secret32::generate().unwrap();
        let server = server(dir.path(), &kek, &clock, limits, trust_proxy);
        Self {
            server,
            clock,
            kek,
            dir,
        }
    }

    fn advance(&self, seconds: i64) {
        self.clock.0.fetch_add(seconds, Ordering::Relaxed);
    }

    fn db(&self) -> Connection {
        Connection::open(self.dir.path().join("tightlip.sqlite3")).unwrap()
    }

    fn blob_count(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("blobs"))
            .unwrap()
            .count()
    }

    fn assert_destroyed(&self, id: &ShareId) {
        let db = self.db();
        let remaining: (i64, i64, i64, i64, i64) = db
            .query_row(
                "SELECT COUNT(*), COUNT(wrapped_key), COUNT(manifest),
                (SELECT COUNT(*) FROM files WHERE share_id = ?1),
                (SELECT COUNT(*) FROM grants WHERE share_id = ?1)
             FROM shares WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(remaining, (0, 0, 0, 0, 0));
        assert_eq!(self.blob_count(), 0);
    }
}

fn server(
    dir: &Path,
    kek: &Secret32,
    clock: &Arc<TestClock>,
    limits: Limits,
    trust_proxy: bool,
) -> Server {
    Server::open(
        Config {
            port: 0,
            data_dir: dir.to_owned(),
            web_dir: dir.join("web"),
            public_url: None,
            kek: Secret32::from_bytes(*kek.as_bytes()),
            trust_proxy,
            limits,
        },
        clock.clone(),
    )
    .unwrap()
}

struct Pending {
    id: ShareId,
    path: String,
    link: Secret32,
    owner: Secret32,
    upload: Zeroizing<String>,
    keys: ShareKeys,
    expires_at: i64,
}

impl Pending {
    async fn create(app: &Router, password: Option<&str>, views: u32, ttl_seconds: u32) -> Self {
        let link = Secret32::generate().unwrap();
        let owner = Secret32::generate().unwrap();
        let (blinded, client) = share::start(&link, password).unwrap();
        let response = send(
            app,
            create_request(blinded, views, ttl_seconds, password.is_some()),
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);
        let mut created = response.json();
        let id = bytes(&created["id"]).try_into().unwrap();
        let upload = Zeroizing::new(created["upload_token"].take().as_str().unwrap().to_owned());
        let keys = client.finish(&bytes(&created["evaluated"]), &id).unwrap();
        Self {
            id,
            path: format!("/api/v1/shares/{}", b64::encode(&id)),
            link,
            owner,
            upload,
            keys,
            expires_at: created["expires_at"].as_i64().unwrap(),
        }
    }

    async fn upload(&self, app: &Router, parts: &[&[u8]]) -> Vec<Vec<u8>> {
        let files: Vec<_> = parts
            .iter()
            .enumerate()
            .map(|(n, bytes)| FileEntry {
                name: format!("file{n}.bin"),
                mime: "application/octet-stream".into(),
                size: bytes.len() as u64,
                key: Secret32::generate().unwrap(),
            })
            .collect();
        let ciphertexts = parts
            .iter()
            .zip(&files)
            .enumerate()
            .map(|(n, (bytes, entry))| {
                manifest::seal_file(&self.id, n as u32, entry, bytes).unwrap()
            })
            .collect::<Vec<_>>();
        let manifest = Manifest {
            v: VERSION,
            note: Some("private note".into()),
            login: None,
            files: Some(files),
        };
        let ciphertext =
            manifest::seal_manifest(&self.keys.manifest_key, &self.id, &manifest).unwrap();
        let response = send(app, self.put("manifest", Body::from(ciphertext))).await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        for (n, ciphertext) in ciphertexts.iter().enumerate() {
            let body = stream_chunks(
                ciphertext
                    .chunks(4096)
                    .map(Bytes::copy_from_slice)
                    .collect(),
            );
            let response = send(app, self.put(&format!("files/{n}"), body)).await;
            assert_eq!(response.status, StatusCode::NO_CONTENT);
        }
        ciphertexts
    }

    async fn commit(&self, app: &Router) {
        let response = send(app, self.commit_request(self.commit_body())).await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert!(response.body.is_empty());
    }

    fn commit_body(&self) -> Value {
        json!({
            "access_verifier": b64::encode(&share::access_verifier(&self.keys.access_tag)),
            "owner_verifier": b64::encode(&share::owner_verifier(&self.owner)),
        })
    }

    fn commit_request(&self, body: Value) -> Request<Body> {
        json_request(
            Method::POST,
            &format!("{}/commit", &self.path),
            Some(&self.upload),
            body,
        )
    }

    fn put(&self, object: &str, body: Body) -> Request<Body> {
        request(
            Method::PUT,
            &format!("{}/{object}", &self.path),
            Some(&self.upload),
            Some("application/octet-stream"),
            body,
        )
    }

    async fn info(&self, app: &Router) -> Received {
        send(
            app,
            request(Method::GET, &self.path, None, None, Body::empty()),
        )
        .await
    }

    async fn reveal(&self, app: &Router) -> Value {
        let response = send(app, open_request(&self.path, &self.keys.access_tag)).await;
        assert_eq!(response.status, StatusCode::OK);
        response.json()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Received {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Received {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn assert_error(&self, status: StatusCode, code: &str) {
        assert_eq!(self.status, status);
        assert_eq!(self.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(self.body, format!(r#"{{"error":"{code}"}}"#));
    }
}

async fn send(app: &Router, mut request: Request<Body>) -> Received {
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:46312".parse::<SocketAddr>().unwrap(),
    ));
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    Received {
        status: parts.status,
        headers: parts.headers,
        body: to_bytes(body, 2_000_000).await.unwrap(),
    }
}

fn request(
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    request.body(body).unwrap()
}

fn json_request(method: Method, path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    request(
        method,
        path,
        token,
        Some("application/json"),
        Body::from(body.to_string()),
    )
}

fn stream_chunks(chunks: Vec<Bytes>) -> Body {
    Body::from_stream(futures_util::stream::iter(
        chunks.into_iter().map(Ok::<_, Infallible>),
    ))
}

fn create_request(
    blinded: [u8; 32],
    views: u32,
    ttl_seconds: u32,
    has_password: bool,
) -> Request<Body> {
    json_request(
        Method::POST,
        "/api/v1/shares",
        None,
        json!({
            "suite": labels::SUITE, "blinded": b64::encode(&blinded),
            "ttl_seconds": ttl_seconds, "max_views": views, "has_password": has_password,
        }),
    )
}

fn eval_request(path: &str, blinded: &[u8; 32]) -> Request<Body> {
    json_request(
        Method::POST,
        &format!("{path}/eval"),
        None,
        json!({"blinded": b64::encode(blinded)}),
    )
}

fn open_request(path: &str, tag: &Secret32) -> Request<Body> {
    json_request(
        Method::POST,
        &format!("{path}/open"),
        None,
        json!({"access_tag": b64::encode(tag.as_bytes())}),
    )
}

fn download_request(path: &str, n: usize, grant: &str) -> Request<Body> {
    request(
        Method::GET,
        &format!("{path}/files/{n}"),
        Some(grant),
        None,
        Body::empty(),
    )
}

fn bytes(value: &Value) -> Vec<u8> {
    b64::decode(value.as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn full_client_cycle_with_and_without_password() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let large = vec![0x42; CHUNK_LEN + 1];
    let files: [&[u8]; 2] = [b"one\0\x80", &large];
    for password in [None, Some("test password with NFKC: ｐ")] {
        let pending = Pending::create(&app, password, 1, 3600).await;
        let ciphertexts = pending.upload(&app, &files).await;
        pending.commit(&app).await;
        assert_eq!(
            pending.info(&app).await.json(),
            json!({
                "suite": labels::SUITE, "has_password": password.is_some(),
                "expires_at": START + 3600, "views_left": 1
            })
        );
        assert_eq!(pending.expires_at, START + 3600);
        let (blinded, client) = share::start(&pending.link, password).unwrap();
        let response = send(&app, eval_request(&pending.path, &blinded)).await;
        assert_eq!(response.status, StatusCode::OK);
        let eval = response.json();
        assert_eq!(
            eval["attempts_left"],
            if password.is_some() { 5 } else { 3 }
        );
        let keys = client
            .finish(&bytes(&eval["evaluated"]), &pending.id)
            .unwrap();
        let response = send(&app, open_request(&pending.path, &keys.access_tag)).await;
        assert_eq!(response.status, StatusCode::OK);
        let opened = response.json();
        let listed = opened["files"].as_array().unwrap();
        let manifest = manifest::open_manifest(
            &keys.manifest_key,
            &pending.id,
            &bytes(&opened["manifest"]),
            listed.len(),
        )
        .unwrap();
        assert_eq!(manifest.note.as_deref(), Some("private note"));
        let grant = opened["grant"].as_str().unwrap();
        for (n, file) in manifest.files.as_ref().unwrap().iter().enumerate() {
            let response = send(&app, download_request(&pending.path, n, grant)).await;
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(
                response.headers[header::CONTENT_TYPE],
                "application/octet-stream"
            );
            assert_eq!(listed[n], json!({"n": n, "size": ciphertexts[n].len()}));
            assert_eq!(response.body.as_ref(), ciphertexts[n]);
            let decrypted =
                manifest::open_file(&pending.id, n as u32, file, &response.body).unwrap();
            assert_eq!(decrypted.as_bytes(), files[n]);
        }
        assert_eq!(pending.info(&app).await.status, StatusCode::NOT_FOUND);
        let db = fixture.db();
        let state: (bool, bool, Option<Vec<u8>>) = db.query_row(
            "SELECT wrapped_key IS NULL, manifest IS NULL, upload_hash FROM shares WHERE id = ?1",
            params![pending.id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(state, (true, true, None));
        let hash: Vec<u8> = db
            .query_row(
                "SELECT hash FROM grants WHERE share_id = ?1",
                params![pending.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, b64::decode(grant).unwrap());
        let owner = Zeroizing::new(b64::encode(pending.owner.as_bytes()));
        let response = send(
            &app,
            request(
                Method::DELETE,
                &pending.path,
                Some(&owner),
                None,
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        fixture.assert_destroyed(&pending.id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fifty_opens_can_spend_exactly_three_views() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 3, 3600).await;
    pending.upload(&app, &[]).await;
    pending.commit(&app).await;
    let mut opens = JoinSet::new();
    for _ in 0..50 {
        let app = app.clone();
        let request = open_request(&pending.path, &pending.keys.access_tag);
        opens.spawn(async move { send(&app, request).await.status });
    }
    let mut successes = 0;
    while let Some(status) = opens.join_next().await {
        match status.unwrap() {
            StatusCode::OK => successes += 1,
            StatusCode::NOT_FOUND => {}
            status => panic!("unexpected status {status}"),
        }
    }
    assert_eq!(successes, 3);
}

#[tokio::test]
async fn wrong_tag_spends_no_view_and_password_guesses_destroy_the_share() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, Some("creation test password"), 1, 3600).await;
    pending.upload(&app, &[b"blob to destroy"]).await;
    pending.commit(&app).await;
    let (blinded, wrong) = share::start(&pending.link, Some("wrong test password")).unwrap();
    let invalid = send(&app, eval_request(&pending.path, &[0; 32])).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let response = send(&app, eval_request(&pending.path, &blinded)).await;
    assert_eq!(response.status, StatusCode::OK);
    let first = response.json();
    assert_eq!(first["attempts_left"], 5);
    let wrong = wrong
        .finish(&bytes(&first["evaluated"]), &pending.id)
        .unwrap();
    let response = send(&app, open_request(&pending.path, &wrong.access_tag)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(pending.info(&app).await.json()["views_left"], 1);
    for attempts_left in (0..5).rev() {
        let response = send(&app, eval_request(&pending.path, &blinded)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["attempts_left"], attempts_left);
    }
    assert_eq!(pending.info(&app).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        send(&app, eval_request(&pending.path, &blinded))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    fixture.assert_destroyed(&pending.id);
}

#[tokio::test]
async fn unavailable_shares_have_identical_recipient_responses() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let expired = Pending::create(&app, None, 2, 300).await;
    expired.upload(&app, &[b"expired"]).await;
    expired.commit(&app).await;
    let expired_grant = expired.reveal(&app).await;
    fixture.advance(300);
    let pending = Pending::create(&app, None, 1, 3600).await;
    pending.upload(&app, &[b"pending"]).await;
    let burned = Pending::create(&app, None, 1, 3600).await;
    burned.upload(&app, &[b"burned"]).await;
    burned.commit(&app).await;
    burned.reveal(&app).await;
    let missing = format!(
        "/api/v1/shares/{}",
        b64::encode(&share::generate_share_id().unwrap())
    );
    let (blinded, _) = share::start(&expired.link, None).unwrap();
    let grant = expired_grant["grant"].as_str().unwrap();
    let baseline = send(
        &app,
        request(Method::GET, &missing, None, None, Body::empty()),
    )
    .await;
    baseline.assert_error(StatusCode::NOT_FOUND, "not_found");
    for route in 0..5 {
        let make = |path: &str| match route {
            0 => request(Method::GET, path, None, None, Body::empty()),
            1 => eval_request(path, &blinded),
            2 => open_request(path, &expired.keys.access_tag),
            3 => download_request(path, 0, grant),
            _ => request(
                Method::POST,
                &format!("{path}/open"),
                None,
                None,
                Body::empty(),
            ),
        };
        for path in [&missing, &expired.path, &pending.path, &burned.path] {
            assert_eq!(send(&app, make(path)).await, baseline);
        }
    }
}

#[tokio::test]
async fn expiry_and_stale_pending_sweep_remove_rows_and_files() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let live = Pending::create(&app, None, 2, 300).await;
    live.upload(&app, &[b"first", b"second"]).await;
    live.commit(&app).await;
    let opened = live.reveal(&app).await;
    let pending = Pending::create(&app, None, 2, 3600).await;
    pending.upload(&app, &[b"stale pending"]).await;
    assert_eq!(fixture.blob_count(), 3);
    let before: (bool, bool) = fixture
        .db()
        .query_row(
            "SELECT wrapped_key IS NOT NULL, manifest IS NOT NULL FROM shares WHERE id = ?1",
            params![live.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, (true, true));
    fixture.advance(900);
    assert_eq!(
        send(
            &app,
            download_request(&live.path, 0, opened["grant"].as_str().unwrap())
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let response = send(&app, pending.put("manifest", Body::from("stale"))).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    fixture.server.sweep().await.unwrap();
    fixture.assert_destroyed(&live.id);
    fixture.assert_destroyed(&pending.id);
}

#[tokio::test]
async fn grants_survive_restart_and_keep_blobs_until_the_last_grant_expires() {
    let Fixture {
        server: original,
        clock,
        kek,
        dir,
    } = Fixture::new(Limits::default());
    let app = original.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    let ciphertext = pending.upload(&app, &[b"download continues"]);
    let ciphertext = ciphertext.await;
    pending.commit(&app).await;
    let first = pending.reveal(&app).await;
    clock.0.fetch_add(120, Ordering::Relaxed);
    let last = pending.reveal(&app).await;
    drop(app);
    drop(original);

    let restarted = server(dir.path(), &kek, &clock, Limits::default(), false);
    let fixture = Fixture {
        server: restarted,
        clock,
        kek,
        dir,
    };
    let app = fixture.server.router();
    let download =
        |grant: &Value| download_request(&pending.path, 0, grant["grant"].as_str().unwrap());
    assert_eq!(
        send(&app, download(&first)).await.body.as_ref(),
        ciphertext[0]
    );
    fixture.advance(480);
    fixture.server.sweep().await.unwrap();
    assert_eq!(
        send(&app, download(&first)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, download(&last)).await.body.as_ref(),
        ciphertext[0]
    );
    assert_eq!(fixture.blob_count(), 1);
    fixture.advance(120);
    assert_eq!(
        send(&app, download(&last)).await.status,
        StatusCode::NOT_FOUND
    );
    fixture.server.sweep().await.unwrap();
    fixture.assert_destroyed(&pending.id);
}

#[tokio::test]
async fn commit_invalidates_upload_token_and_delete_needs_the_owner_token() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    pending.upload(&app, &[b"owner can remove this"]).await;
    let stored: Vec<u8> = fixture
        .db()
        .query_row(
            "SELECT upload_hash FROM shares WHERE id = ?1",
            params![pending.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, b64::decode(&pending.upload).unwrap());
    pending.commit(&app).await;
    for target in ["manifest", "files/0", "files/2"] {
        let response = send(&app, pending.put(target, Body::from("ciphertext"))).await;
        response.assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    for body in [pending.commit_body(), json!({"unexpected": true})] {
        send(&app, pending.commit_request(body))
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    let delete = |token: &str| {
        request(
            Method::DELETE,
            &pending.path,
            Some(token),
            None,
            Body::empty(),
        )
    };
    for wrong in [
        &*pending.upload,
        &b64::encode(Secret32::generate().unwrap().as_bytes()),
    ] {
        send(&app, delete(wrong))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let owner = Zeroizing::new(b64::encode(pending.owner.as_bytes()));
    assert_eq!(
        send(&app, delete(&owner)).await.status,
        StatusCode::NO_CONTENT
    );
    fixture.assert_destroyed(&pending.id);
}

#[tokio::test]
async fn streaming_limits_reject_excess_ciphertext_without_orphaned_blobs() {
    let fixture = Fixture::new(Limits {
        manifest_bytes: 600,
        files_per_share: 2,
        total_ciphertext_bytes: 690,
        ..Limits::default()
    });
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    let large = stream_chunks(vec![Bytes::from(vec![0; 500]), Bytes::from(vec![0; 101])]);
    send(&app, pending.put("manifest", large))
        .await
        .assert_error(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    assert_eq!(fixture.blob_count(), 0);
    pending.upload(&app, &[b"first"]).await;
    assert_eq!(fixture.blob_count(), 1);
    let extra_file = send(
        &app,
        pending.put("files/2", Body::from("one file too many")),
    )
    .await;
    assert_eq!(extra_file.status, StatusCode::PAYLOAD_TOO_LARGE);
    let excess_total = stream_chunks(vec![
        Bytes::from_static(b"123456789"),
        Bytes::from_static(b"abcdefghijklmnopqrstuvwxyz"),
    ]);
    assert_eq!(
        send(&app, pending.put("files/1", excess_total))
            .await
            .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(fixture.blob_count(), 1);
    let files: i64 = fixture
        .db()
        .query_row(
            "SELECT COUNT(*) FROM files WHERE share_id = ?1",
            params![pending.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(files, 1);
}

#[tokio::test]
async fn size_order_and_auth_are_rechecked_after_streaming() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    pending.upload(&app, &[]).await;
    let denied = send(&app, pending.put("files/1", Body::from("index gap"))).await;
    denied.assert_error(StatusCode::CONFLICT, "conflict");

    let (started, ready) = tokio::sync::oneshot::channel();
    let (finish, committed) = tokio::sync::oneshot::channel();
    let chunks = futures_util::stream::once(Box::pin(async move {
        started.send(()).unwrap();
        committed.await.unwrap();
        Ok::<_, Infallible>(Bytes::from_static(b"body delivered after commit"))
    }));
    let request = pending.put("files/0", Body::from_stream(chunks));
    let upload_app = app.clone();
    let upload = tokio::spawn(async move { send(&upload_app, request).await });
    ready.await.unwrap();
    pending.commit(&app).await;
    finish.send(()).unwrap();
    assert_eq!(upload.await.unwrap().status, StatusCode::NOT_FOUND);
    assert_eq!(fixture.blob_count(), 0);
}

#[tokio::test]
async fn only_trusted_last_forwarded_hop_affects_the_in_memory_rate_limit() {
    for trust_proxy in [false, true] {
        let fixture = Fixture::with_proxy(
            Limits {
                creates_per_ip: 1,
                ..Limits::default()
            },
            trust_proxy,
        );
        let app = fixture.server.router();
        let (blinded, _) = share::start(&Secret32::generate().unwrap(), None).unwrap();
        let create = |chain: &'static str| {
            let mut request = create_request(blinded, 1, 3600, false);
            request
                .headers_mut()
                .insert("x-forwarded-for", chain.parse().unwrap());
            request
        };
        assert_eq!(
            send(&app, create("192.0.2.2, 192.0.2.3")).await.status,
            StatusCode::CREATED
        );
        assert_eq!(
            send(&app, create("192.0.2.4, 192.0.2.3")).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
        let status = send(&app, create("192.0.2.4, 192.0.2.5")).await.status;
        assert_eq!(
            status,
            if trust_proxy {
                StatusCode::CREATED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        fixture.advance(3600);
        assert_eq!(
            send(&app, create("192.0.2.2, 192.0.2.3")).await.status,
            StatusCode::CREATED
        );
    }
}

#[tokio::test]
async fn retry_after_rounds_up_the_time_until_a_token_refills() {
    let fixture = Fixture::new(Limits {
        creates_per_ip: 7,
        ..Limits::default()
    });
    let app = fixture.server.router();
    let (blinded, _) = share::start(&Secret32::generate().unwrap(), None).unwrap();
    let create = || create_request(blinded, 1, 3600, false);
    for _ in 0..7 {
        assert_eq!(send(&app, create()).await.status, StatusCode::CREATED);
    }
    let denied = send(&app, create()).await;
    denied.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(denied.headers[header::RETRY_AFTER], "515");
    fixture.advance(514);
    let denied = send(&app, create()).await;
    denied.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(denied.headers[header::RETRY_AFTER], "1");
    fixture.advance(1);
    assert_eq!(send(&app, create()).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn request_json_rejects_unknown_fields_and_incorrect_content_types() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    let (blinded, _) = share::start(&pending.link, None).unwrap();
    let unknown = |mut body: Value| {
        body["unexpected"] = json!(true);
        body
    };
    let create = create_request(blinded, 1, 3600, false);
    let data = to_bytes(create.into_body(), 16_000).await.unwrap();
    let create_body = serde_json::from_slice(&data).unwrap();
    for request in [
        json_request(Method::POST, "/api/v1/shares", None, unknown(create_body)),
        pending.commit_request(unknown(pending.commit_body())),
        request(
            Method::POST,
            "/api/v1/shares",
            None,
            Some("text/plain"),
            Body::from(data),
        ),
        request(
            Method::POST,
            "/api/v1/shares",
            None,
            Some("application/json"),
            Body::from("{"),
        ),
        request(
            Method::PUT,
            &format!("{}/manifest", pending.path),
            Some(&pending.upload),
            Some("application/json"),
            Body::from("{}"),
        ),
        request(Method::GET, "/api/v1/shares/%FF", None, None, Body::empty()),
        request(
            Method::GET,
            "/api/v1/shares/invalid-id",
            None,
            None,
            Body::empty(),
        ),
    ] {
        send(&app, request)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "bad_request");
    }
    pending.upload(&app, &[]).await;
    pending.commit(&app).await;
    for (route, body) in [
        ("eval", json!({"blinded": b64::encode(&blinded)})),
        (
            "open",
            json!({"access_tag": b64::encode(pending.keys.access_tag.as_bytes())}),
        ),
    ] {
        let path = format!("{}/{route}", pending.path);
        send(&app, json_request(Method::POST, &path, None, unknown(body)))
            .await
            .assert_error(StatusCode::BAD_REQUEST, "bad_request");
    }
    assert_eq!(pending.info(&app).await.json()["views_left"], 2);
    let response = send(&app, eval_request(&pending.path, &blinded)).await;
    assert_eq!(response.json()["attempts_left"], 4);
}

#[tokio::test]
async fn download_requires_a_valid_grant_and_masks_unavailable_shares() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    pending.upload(&app, &[b"one blob"]).await;
    pending.commit(&app).await;
    let wrong = Zeroizing::new(b64::encode(Secret32::generate().unwrap().as_bytes()));
    send(&app, download_request(&pending.path, 0, &wrong))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthorized");
    let opened = pending.reveal(&app).await;
    let grant = opened["grant"].as_str().unwrap();
    send(&app, download_request(&pending.path, 1, grant))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    fixture.advance(600);
    send(&app, download_request(&pending.path, 0, grant))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthorized");
    pending.reveal(&app).await;
    send(&app, download_request(&pending.path, 0, grant))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
}

#[tokio::test]
async fn internal_errors_use_the_same_json_shape() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 2, 3600).await;
    pending.upload(&app, &[]).await;
    pending.commit(&app).await;
    fixture
        .db()
        .execute(
            "UPDATE shares SET wrapped_key = x'00' WHERE id = ?1",
            params![pending.id],
        )
        .unwrap();
    let (blinded, _) = share::start(&pending.link, None).unwrap();
    send(&app, eval_request(&pending.path, &blinded))
        .await
        .assert_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
}

#[test]
fn binary_refuses_to_start_with_missing_or_malformed_kek() {
    for value in [None, Some("malformed!"), Some("AA")] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_tightlip"));
        process.env_remove("TIGHTLIP_KEK");
        if let Some(value) = value {
            process.env("TIGHTLIP_KEK", value);
        }
        let output = process.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr.trim(),
            "tightlip: missing or invalid environment variable TIGHTLIP_KEK"
        );
        if let Some(value) = value {
            assert!(!stderr.contains(value));
        }
    }
}

#[tokio::test]
async fn api_health_and_fallback_carry_the_required_headers() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let pending = Pending::create(&app, None, 1, 3600).await;
    pending.upload(&app, &[]).await;
    pending.commit(&app).await;
    for (path, status, cache) in [
        ("/healthz", StatusCode::OK, None),
        ("/", StatusCode::NOT_FOUND, None),
        (&pending.path, StatusCode::OK, Some("no-store")),
        ("/api/v1/unknown", StatusCode::NOT_FOUND, Some("no-store")),
        ("/api/v1/shares", StatusCode::NOT_FOUND, Some("no-store")),
    ] {
        let response = send(&app, request(Method::GET, path, None, None, Body::empty())).await;
        assert_eq!(response.status, status);
        assert_security_headers(&response);
        assert_eq!(
            response
                .headers
                .get(header::CACHE_CONTROL)
                .map(|value| value.to_str().unwrap()),
            cache
        );
        if path == "/healthz" {
            assert_eq!(response.body, "ok");
        } else if status == StatusCode::NOT_FOUND {
            response.assert_error(StatusCode::NOT_FOUND, "not_found");
        }
    }
}

fn assert_security_headers(response: &Received) {
    let spec = include_str!("../../../docs/SPEC.md");
    let (_, section) = spec.split_once("## 8. Web delivery").unwrap();
    let block = section.split("```").nth(1).unwrap();
    assert_eq!(block.trim().lines().count(), 8);
    for line in block.trim().lines() {
        let (name, value) = line.split_once(": ").unwrap();
        assert_eq!(response.headers[name], value);
    }
}

#[tokio::test]
async fn static_routes_serve_the_index_and_immutable_assets() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let web_dir = fixture.dir.path().join("web");
    let share_id = b64::encode(&share::generate_share_id().unwrap());
    let path = format!("/s/{share_id}");
    let get = |path| request(Method::GET, path, None, None, Body::empty());
    for dir_exists in [false, true] {
        if dir_exists {
            fs::create_dir(&web_dir).unwrap();
        }
        for route in ["/", &path] {
            send(&app, get(route))
                .await
                .assert_error(StatusCode::NOT_FOUND, "not_found");
        }
    }

    let html = b"<!doctype html><title>Test bundle</title>";
    let wasm = b"\0asm\x01\0\0\0";
    let js = b"export {};";
    fs::create_dir_all(web_dir.join("assets/nested")).unwrap();
    fs::write(web_dir.join("index.html"), html).unwrap();
    fs::write(web_dir.join("assets/nested/core-Ab3.wasm"), wasm).unwrap();
    fs::write(web_dir.join("assets/app-Ab3.js"), js).unwrap();
    for route in ["/", &path] {
        let response = send(&app, get(route)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), html);
        assert_eq!(
            response.headers[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(response.headers[header::CACHE_CONTROL], "no-cache");
        assert_security_headers(&response);
    }
    for (route, content_type, body) in [
        (
            "/assets/nested/core-Ab3.wasm",
            "application/wasm",
            wasm.as_slice(),
        ),
        (
            "/assets/app-Ab3.js",
            "text/javascript; charset=utf-8",
            js.as_slice(),
        ),
    ] {
        let response = send(&app, get(route)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, body);
        assert_eq!(response.headers[header::CONTENT_TYPE], content_type);
        assert_eq!(
            response.headers[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_security_headers(&response);
    }
}

#[tokio::test]
async fn static_routes_reject_traversal_and_directory_listings() {
    let fixture = Fixture::new(Limits::default());
    let app = fixture.server.router();
    let web_dir = fixture.dir.path().join("web");
    fs::create_dir_all(web_dir.join("assets/nested")).unwrap();
    fs::write(web_dir.join("index.html"), "test index").unwrap();
    let outside = fixture.dir.path().join("outside.txt");
    fs::write(&outside, "outside the web root").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, web_dir.join("assets/escape.txt")).unwrap();

    for route in [
        "/assets",
        "/assets/",
        "/assets/nested",
        "/assets/nested/",
        "/assets/..%2f..%2fCargo.toml",
        "/assets/%2e%2e%2f%2e%2e%2foutside.txt",
        "/assets/..%5c..%5coutside.txt",
        "/assets/..%2findex.html",
        "/assets/escape.txt",
        "/assets/%ff",
        "/index.html",
        "/s/",
        "/s/id/extra",
        "/api/v2/shares",
    ] {
        let response = send(&app, request(Method::GET, route, None, None, Body::empty())).await;
        response.assert_error(StatusCode::NOT_FOUND, "not_found");
        assert_security_headers(&response);
    }
}
