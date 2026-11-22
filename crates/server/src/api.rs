use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, Request},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use tightlip_core::{
    Secret32, b64, labels,
    oprf::ServerKey,
    share::{self, ShareId, Verifier},
};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::{
    Server, State,
    credentials::{bearer, deserialize_secret, token_hash},
    storage::{Blob, Error, FileInfo, Pending, Result, ShareInfo, Upload, UploadTarget},
    web,
};

const JSON_CAP: u64 = 16_000;
const BINARY: &str = "application/octet-stream";
const CSP: &str = concat!(
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; ",
    "img-src 'self' blob:; media-src blob:; font-src 'self'; connect-src 'self'; ",
    "worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; ",
    "frame-ancestors 'none'; require-trusted-types-for 'script'",
);
const SECURITY_HEADERS: [(&str, &str); 8] = [
    ("content-security-policy", CSP),
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
        .route("/s/{id}", get(web::index))
        .route("/assets/{*path}", get(web::asset))
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
            Self::FileGap => (StatusCode::CONFLICT, "conflict"),
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
            state.meta.create(&pending)?;
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
    let target = require_type(request.headers(), BINARY).map(|()| UploadTarget::Manifest);
    let (upload, cap) = prepare_upload(&server, &id, target, request.headers()).await?;
    let mut body = request.into_body().into_data_stream();
    let mut data = Vec::new();
    let mut size = 0;
    while let Some(chunk) = body.next().await {
        let chunk = checked_chunk(chunk, &mut size, cap)?;
        data.extend_from_slice(&chunk);
    }
    if data.is_empty() {
        return Err(Error::Invalid);
    }
    server
        .run(move |state| state.meta.put_manifest(&upload, state.clock.now(), &data))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_file(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath((id, n)): ApiPath<(String, String)>,
    request: Request,
) -> Result<StatusCode> {
    let target = require_type(request.headers(), BINARY)
        .and_then(|()| file_index(&n))
        .map(UploadTarget::File);
    let (upload, cap) = prepare_upload(&server, &id, target, request.headers()).await?;
    let mut stage = server.run(|state| state.blobs.stage()).await?;
    let mut body = request.into_body().into_data_stream();
    let mut size = 0;
    let mut writer = stage.writer()?;
    while let Some(chunk) = body.next().await {
        let chunk = checked_chunk(chunk, &mut size, cap)?;
        writer.write_all(&chunk).await?;
    }
    if size == 0 {
        return Err(Error::Invalid);
    }
    writer.shutdown().await?;
    server
        .run(move |state| {
            let blob = Blob {
                key: stage.key(),
                size,
            };
            state
                .meta
                .put_file(&upload, state.clock.now(), &blob, &mut || stage.publish())?;
            stage.keep();
            let _ = state.meta.collect_garbage(&*state.blobs);
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn prepare_upload(
    server: &Server,
    id: &str,
    target: Result<UploadTarget>,
    headers: &HeaderMap,
) -> Result<(Upload, u64)> {
    let id = decode(id).ok_or(Error::Invalid)?;
    let hash = bearer(headers).as_ref().map(token_hash);
    server
        .run(move |state| {
            let now = state.clock.now();
            if target.is_err() {
                state.meta.check_pending_upload(&id, now, hash.as_ref())?;
            }
            let upload = Upload {
                id,
                hash,
                target: target?,
                manifest_cap: u64::from(state.limits.manifest_bytes),
                file_cap: state.limits.files_per_share,
                total_cap: state.limits.total_ciphertext_bytes,
            };
            let cap = state.meta.upload_limit(&upload, now)?;
            Ok((upload, cap))
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
            if attempts_left == 0 {
                let _ = state.meta.collect_garbage(&*state.blobs);
            }
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
}

#[derive(Serialize)]
struct OpenResponse {
    manifest: String,
    files: Vec<FileInfo>,
    #[serde(serialize_with = "serialize_secret")]
    grant: Secret32,
}

async fn open(
    axum::extract::State(server): axum::extract::State<Server>,
    ApiPath(id): ApiPath<String>,
    request: Request,
) -> Result<Json<OpenResponse>> {
    let id = decode(&id).ok_or(Error::Invalid)?;
    let tag = json::<Open>(request).await.map(|body| body.access_tag);
    server
        .run(move |state| {
            let grant = Secret32::generate().map_err(|_| Error::Internal)?;
            let opened = state
                .meta
                .open(&id, state.clock.now(), tag, &token_hash(&grant))?;
            Ok(Json(OpenResponse {
                manifest: b64::encode(&opened.manifest),
                files: opened.files,
                grant,
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
            let body = state.blobs.download(&blob.key)?;
            Ok((
                [(header::CONTENT_TYPE, BINARY)],
                [(header::CONTENT_LENGTH, blob.size.to_string())],
                body,
            )
                .into_response())
        })
        .await
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
    while let Some(chunk) = body.next().await {
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
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .to_canonical()
}
