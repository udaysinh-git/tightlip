use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{BodyDataStream, Bytes},
    extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, Request},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tightlip_core::{
    Secret32, b64, labels,
    oprf::ServerKey,
    share::{self, ShareId, Verifier},
    stream::{CHUNK_CIPHERTEXT_LEN, HEADER_LEN},
};
use tokio::{
    io::AsyncWriteExt,
    sync::OwnedSemaphorePermit,
    time::{Instant as Deadline, timeout_at},
};
use zeroize::Zeroizing;

use crate::{
    Peer, Server, State,
    credentials::{bearer, deserialize_secret, token_hash},
    storage::{
        Blob, Error, FileInfo, OpenRequest, Pending, Result, ShareInfo, Upload, UploadTarget,
    },
    web,
};

const JSON_CAP: u64 = 16_000;
const BINARY: &str = "application/octet-stream";
const UPLOAD_IDLE: Duration = Duration::from_secs(30);
const UPLOAD_TIME: Duration = Duration::from_secs(15 * 60);
const JSON_TIME: Duration = Duration::from_secs(10);
const CSP: &str = concat!(
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; ",
    "img-src 'self' blob:; font-src 'self'; connect-src 'self'; ",
    "worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; ",
    "frame-ancestors 'none'; require-trusted-types-for 'script'; ",
    "trusted-types tightlip-templates tightlip-worker",
);
const SECURITY_HEADERS: [(&str, &str); 9] = [
    ("content-security-policy", CSP),
    ("integrity-policy", "blocked-destinations=(script)"),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-embedder-policy", "require-corp"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    ),
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    ),
];

pub(crate) fn router(server: Server) -> Router {
    Router::new()
        .route("/api/v1/shares", post(create))
        .route("/api/v1/shares/{id}", get(info).delete(delete))
        .route("/api/v1/shares/{id}/manifest", put(manifest))
        .route("/api/v1/shares/{id}/files/{n}", put(put_file).get(download))
        .route("/api/v1/shares/{id}/commit", post(commit))
        .route("/api/v1/shares/{id}/eval", post(eval))
        .route("/api/v1/shares/{id}/open", post(open))
        .route("/", get(web::index))
        .route("/s/{id}", get(web::share_index))
        .route("/security", get(web::index))
        .route("/robots.txt", get(web::robots))
        .route("/sitemap.xml", get(web::sitemap))
        .route("/og.png", get(web::og_image))
        .route("/assets/{*path}", get(web::asset))
        .route("/.well-known/security.txt", get(web::security_txt))
        .route("/.well-known/tightlip-release.json", get(web::release))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(|| async { Error::Missing })
        .method_not_allowed_fallback(|| async { Error::Missing })
        .layer(middleware::from_fn(response_policy))
        .with_state(server)
}

async fn response_policy(request: Request, next: Next) -> Response {
    let method = match *request.method() {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        _ => "OTHER",
    };
    let route = request.extensions().get::<MatchedPath>().cloned();
    let path = request.uri().path();
    let api = path.starts_with("/api/v1/") || path == "/api/v1";
    let start = Instant::now();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    tracing::info!(
        method,
        route = route.as_ref().map_or("<unmatched>", MatchedPath::as_str),
        status = response.status().as_u16(),
        latency_us = start.elapsed().as_micros(),
    );
    response
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Missing => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::FileGap | Self::UploadInFlight => (StatusCode::CONFLICT, "conflict"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Internal | Self::Io(_) | Self::Sql(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let mut response = (status, Json(ErrorBody { error })).into_response();
        if let Self::RateLimited { retry_after } = self {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        }
        response
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

// Keep Axum's path extraction failures in the API's JSON error format.
struct ApiPath<T>(T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let Path(path) = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| Error::Invalid)?;
        Ok(Self(path))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    suite: String,
    blinded: String,
    ttl_seconds: u32,
    max_views: u32,
    has_password: bool,
}

#[derive(Serialize)]
struct Created {
    id: String,
    evaluated: String,
    #[serde(serialize_with = "serialize_secret")]
    upload_token: Secret32,
    expires_at: i64,
}

async fn create(
    axum::extract::State(server): axum::extract::State<Server>,
    request: Request,
) -> Result<(StatusCode, Json<Created>)> {
    let ip = client_ip(&server.0, &request);
    let body: Create = json(request).await?;
    let limits = server.0.limits;
    if body.suite != labels::SUITE
        || !(limits.min_ttl_seconds..=limits.max_ttl_seconds).contains(&body.ttl_seconds)
        || !(1..=limits.max_views).contains(&body.max_views)
    {
        return Err(Error::Invalid);
    }
    let blinded = decode::<32>(&body.blinded).ok_or(Error::Invalid)?;
    server
        .run(move |state| {
            let now = state.clock.now();
            state.meta.check_storage(limits.storage_bytes)?;
            state.rate.spend(ip, now)?;
            let key = ServerKey::generate().map_err(|_| Error::Internal)?;
            let evaluated = key.blind_evaluate(&blinded).map_err(|_| Error::Invalid)?;
            let id = share::generate_share_id().map_err(|_| Error::Internal)?;
            let wrapped_key =
                share::wrap_oprf_key(&state.kek, &id, &key).map_err(|_| Error::Internal)?;
            let upload_token = Secret32::generate().map_err(|_| Error::Internal)?;
            let extra = if body.has_password {
                limits.password_attempts_extra
            } else {
                limits.passwordless_attempts_extra
            };
            let pending = Pending {
                id,
                expires_at: now.saturating_add(i64::from(body.ttl_seconds)),
                pending_until: now.saturating_add(i64::from(limits.pending_lifetime_seconds)),
                has_password: body.has_password,
                views: body.max_views,
                attempts: body.max_views.checked_add(extra).ok_or(Error::Invalid)?,
                upload_hash: token_hash(&upload_token),
                wrapped_key,
            };
            state.meta.create(&pending, limits.storage_bytes)?;
            Ok((
                StatusCode::CREATED,
                Json(Created {
                    id: b64::encode(&id),
                    evaluated: b64::encode(&evaluated),
                    upload_token,
                    expires_at: pending.expires_at,
                }),
            ))
        })
        .await
}

async fn manifest(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    request: Request,
) -> Result<StatusCode> {
    let deadline = Deadline::now() + UPLOAD_TIME;
    let target = require_type(request.headers(), BINARY).map(|()| UploadTarget::Manifest);
    let (upload, cap, slot, permit) = timeout_at(
        deadline,
        prepare_upload(&server, &id, target, request.headers()),
    )
    .await
    .map_err(|_| Error::Invalid)??;
    let mut body = request.into_body().into_data_stream();
    let mut data = Vec::new();
    let mut size = 0;
    while let Some(chunk) = upload_chunk(&mut body, deadline).await? {
        let chunk = checked_chunk(chunk, &mut size, cap)?;
        data.extend_from_slice(&chunk);
    }
    if data.is_empty() {
        return Err(Error::Invalid);
    }
    server
        .run(move |state| {
            let (_permit, _slot) = (permit, slot);
            check_upload_deadline(deadline)?;
            state.meta.put_manifest(&upload, state.clock.now(), &data)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_file(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath((id, n)): ApiPath<(String, String)>,
    request: Request,
) -> Result<StatusCode> {
    let deadline = Deadline::now() + UPLOAD_TIME;
    let target = require_type(request.headers(), BINARY)
        .and_then(|()| file_index(&n))
        .map(UploadTarget::File);
    let (upload, cap, slot, permit) = timeout_at(
        deadline,
        prepare_upload(&server, &id, target, request.headers()),
    )
    .await
    .map_err(|_| Error::Invalid)??;
    let mut stage = timeout_at(deadline, server.run(|state| state.blobs.stage()))
        .await
        .map_err(|_| Error::Invalid)??;
    let mut body = request.into_body().into_data_stream();
    let mut size = 0;
    let mut writer = stage.writer()?;
    while let Some(chunk) = upload_chunk(&mut body, deadline).await? {
        let chunk = checked_chunk(chunk, &mut size, cap)?;
        timeout_at(deadline, writer.write_all(&chunk))
            .await
            .map_err(|_| Error::Invalid)??;
    }
    if size == 0 {
        return Err(Error::Invalid);
    }
    timeout_at(deadline, writer.shutdown())
        .await
        .map_err(|_| Error::Invalid)??;
    server
        .run(move |state| {
            let (_permit, _slot) = (permit, slot);
            check_upload_deadline(deadline)?;
            let blob = Blob {
                key: stage.key(),
                size,
            };
            stage.publish()?;
            check_upload_deadline(deadline)?;
            state.meta.put_file(&upload, state.clock.now(), &blob)?;
            stage.keep();
            let _ = state.meta.collect_garbage(&*state.blobs);
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

struct UploadSlot {
    slots: Arc<Mutex<HashSet<ShareId>>>,
    id: ShareId,
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.remove(&self.id);
        }
    }
}

fn upload_permit(state: &State) -> Result<OwnedSemaphorePermit> {
    state
        .uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::RateLimited { retry_after: 5 })
}

async fn upload_chunk(
    body: &mut BodyDataStream,
    deadline: Deadline,
) -> Result<Option<std::result::Result<Bytes, axum::Error>>> {
    check_upload_deadline(deadline)?;
    timeout_at(deadline.min(Deadline::now() + UPLOAD_IDLE), body.next())
        .await
        .map_err(|_| Error::Invalid)
}

fn check_upload_deadline(deadline: Deadline) -> Result<()> {
    if Deadline::now() >= deadline {
        return Err(Error::Invalid);
    }
    Ok(())
}

async fn prepare_upload(
    server: &Server,
    id: &str,
    target: Result<UploadTarget>,
    headers: &HeaderMap,
) -> Result<(Upload, u64, UploadSlot, OwnedSemaphorePermit)> {
    let id = decode(id).ok_or(Error::Invalid)?;
    let hash = bearer(headers).as_ref().map(token_hash);
    server
        .run(move |state| {
            let now = state.clock.now();
            state.meta.check_pending_upload(&id, now, hash.as_ref())?;
            let target = target?;
            let slots = state.uploading.clone();
            if !slots.lock().map_err(|_| Error::Internal)?.insert(id) {
                return Err(Error::UploadInFlight);
            }
            let slot = UploadSlot { slots, id };
            let upload = Upload {
                id,
                hash,
                target,
                manifest_cap: u64::from(state.limits.manifest_bytes),
                file_cap: state.limits.files_per_share,
                total_cap: state.limits.total_ciphertext_bytes,
                storage_cap: state.limits.storage_bytes,
            };
            let permit = upload_permit(state)?;
            let cap = state.meta.upload_limit(&upload, now)?;
            Ok((upload, cap, slot, permit))
        })
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    access_verifier: String,
    owner_verifier: String,
}

async fn commit(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    request: Request,
) -> Result<StatusCode> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    let upload = bearer(request.headers()).as_ref().map(token_hash);
    let verifiers = json::<Commit>(request).await.and_then(|body| {
        let access: Verifier = decode(&body.access_verifier).ok_or(Error::Invalid)?;
        let owner: Verifier = decode(&body.owner_verifier).ok_or(Error::Invalid)?;
        Ok((access, owner))
    });
    server
        .run(move |state| {
            state
                .meta
                .commit(&id, state.clock.now(), upload.as_ref(), verifiers)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn info(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<ShareInfo>> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    server
        .run(move |state| state.meta.info(&id, state.clock.now()).map(Json))
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Eval {
    blinded: String,
}

#[derive(Serialize)]
struct Evaluated {
    evaluated: String,
    attempts_left: u32,
}

async fn eval(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    request: Request,
) -> Result<Json<Evaluated>> {
    let id: ShareId = decode(&id).ok_or(Error::Invalid)?;
    let blinded = json::<Eval>(request)
        .await
        .and_then(|body| decode::<32>(&body.blinded).ok_or(Error::Invalid));
    server
        .run(move |state| {
            let (evaluated, attempts_left) = state.meta.eval(
                &id,
                state.clock.now(),
                Box::new(|wrapped| {
                    let (key_id, wrapped) = wrapped
                        .map_or((&state.dummy.id, state.dummy.wrapped.as_slice()), |key| {
                            (&id, key)
                        });
                    let key = share::unwrap_oprf_key(&state.kek, key_id, wrapped)
                        .map_err(|_| Error::Internal)?;
                    let evaluated =
                        key.blind_evaluate(blinded.as_ref().unwrap_or(&state.dummy.blinded));
                    let _ = blinded?;
                    evaluated.map_err(|_| Error::Invalid)
                }),
            )?;
            Ok(Json(Evaluated {
                evaluated: b64::encode(&evaluated),
                attempts_left,
            }))
        })
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    #[serde(deserialize_with = "deserialize_secret")]
    access_tag: Secret32,
    request_id: String,
}

#[derive(Serialize)]
struct OpenResponse {
    manifest: String,
    files: Vec<FileInfo>,
    #[serde(serialize_with = "serialize_secret")]
    grant: Secret32,
    views_left: u32,
}

async fn open(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    request: Request,
) -> Result<Json<OpenResponse>> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    let request = json::<Open>(request).await.and_then(|body| {
        let id = decode::<16>(&body.request_id).ok_or(Error::Invalid)?;
        Ok(OpenRequest {
            tag: body.access_tag,
            request_hash: Sha256::digest(id).into(),
        })
    });
    server
        .run(move |state| {
            let grant = Secret32::generate().map_err(|_| Error::Internal)?;
            let opened = state
                .meta
                .open(&id, state.clock.now(), request, &token_hash(&grant))?;
            Ok(Json(OpenResponse {
                manifest: b64::encode(&opened.manifest),
                files: opened.files,
                grant,
                views_left: opened.views_left,
            }))
        })
        .await
}

async fn download(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath((id, n)): ApiPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    let n = file_index(&n)?;
    let grant = bearer(&headers).as_ref().map(token_hash);
    server
        .run(move |state| {
            let blob = state.meta.file(&id, state.clock.now(), n, grant.as_ref())?;
            let (status, range) = download_range(&headers, blob.size)?;
            let body = state
                .blobs
                .download(&blob.key, range.start, range.end - range.start)?;
            let mut response = (
                status,
                [
                    (header::CONTENT_TYPE, BINARY),
                    (header::ACCEPT_RANGES, "bytes"),
                ],
                [(
                    header::CONTENT_LENGTH,
                    (range.end - range.start).to_string(),
                )],
                body,
            )
                .into_response();
            if status == StatusCode::PARTIAL_CONTENT {
                let value = format!("bytes {}-{}/{}", range.start, range.end - 1, blob.size);
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&value).map_err(|_| Error::Internal)?,
                );
            }
            Ok(response)
        })
        .await
}

fn download_range(headers: &HeaderMap, size: u64) -> Result<(StatusCode, Range<u64>)> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(first) = values.next() else {
        return Ok((StatusCode::OK, 0..size));
    };
    let parse = || {
        let (start, end) = first
            .to_str()
            .ok()?
            .strip_prefix("bytes=")?
            .split_once('-')?;
        let number = |part: &str| {
            if !part.bytes().all(|digit| digit.is_ascii_digit()) {
                return None;
            }
            part.parse::<u64>().ok()
        };
        let start = number(start)?;
        let end = if end.is_empty() {
            size
        } else {
            number(end)?.checked_add(1)?
        };
        Some(start..end)
    };
    let range = parse().ok_or(Error::Invalid)?;
    let aligned = |offset: u64| {
        offset
            .checked_sub(HEADER_LEN as u64)
            .is_some_and(|offset| offset.is_multiple_of(CHUNK_CIPHERTEXT_LEN as u64))
    };
    if values.next().is_some()
        || range.start >= range.end
        || range.end > size
        || (range.start != 0 && !aligned(range.start))
        || (range.end != size && (!aligned(range.end) || range.end == HEADER_LEN as u64))
    {
        return Err(Error::Invalid);
    }
    Ok((StatusCode::PARTIAL_CONTENT, range))
}

async fn delete(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    let owner = bearer(&headers);
    server
        .run(move |state| {
            state.meta.delete(&id, state.clock.now(), owner.as_ref())?;
            let _ = state.meta.collect_garbage(&*state.blobs);
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn decode<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    b64::decode(encoded).ok()?.try_into().ok()
}

fn file_index(n: &str) -> Result<u32> {
    if !n.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Invalid);
    }
    n.parse().map_err(|_| Error::Invalid)
}

fn serialize_secret<S: Serializer>(
    secret: &Secret32,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let text = Zeroizing::new(b64::encode(secret.as_bytes()));
    serializer.serialize_str(&text)
}

async fn json<T: DeserializeOwned>(request: Request) -> Result<T> {
    require_type(request.headers(), "application/json")?;
    let mut data = Zeroizing::new(Vec::with_capacity(JSON_CAP as usize));
    let mut body = request.into_body().into_data_stream();
    let mut size = 0;
    let deadline = Deadline::now() + JSON_TIME;
    while let Some(chunk) = timeout_at(deadline, body.next())
        .await
        .map_err(|_| Error::Invalid)?
    {
        check_upload_deadline(deadline)?;
        let chunk = checked_chunk(chunk, &mut size, JSON_CAP)?;
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| Error::Invalid)
}

fn checked_chunk(
    chunk: std::result::Result<Bytes, axum::Error>,
    size: &mut u64,
    cap: u64,
) -> Result<Bytes> {
    let chunk = chunk.map_err(|_| Error::Invalid)?;
    *size = size
        .checked_add(chunk.len() as u64)
        .ok_or(Error::TooLarge)?;
    if *size > cap {
        return Err(Error::TooLarge);
    }
    Ok(chunk)
}

fn require_type(headers: &HeaderMap, expected: &str) -> Result<()> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let media_type = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next());
    if media_type.is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
        && values.next().is_none()
    {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

fn client_ip(state: &State, request: &Request) -> IpAddr {
    let forwarded = state
        .trust_proxy
        .then(|| {
            request
                .headers()
                .get_all("x-forwarded-for")
                .iter()
                .next_back()
                .and_then(|value| value.to_str().ok())
                .and_then(|chain| chain.rsplit(',').next())
                .and_then(|hop| hop.trim().parse::<IpAddr>().ok())
        })
        .flatten();
    forwarded
        .or_else(|| {
            let extensions = request.extensions();
            extensions
                .get::<ConnectInfo<Peer>>()
                .map(|ConnectInfo(Peer(address))| *address)
                .or_else(|| {
                    extensions
                        .get::<ConnectInfo<SocketAddr>>()
                        .map(|info| info.0)
                })
                .map(|address| address.ip())
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}
