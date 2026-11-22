use std::{
    fs::{self, File},
    io::{self, ErrorKind},
    path::Path as FsPath,
};

use axum::{
    extract::{Path, State, rejection::PathRejection},
    http::header,
    response::{IntoResponse, Response},
};

use crate::{
    Server,
    file_body::file_body,
    storage::{Error, Result},
};

pub(crate) async fn index(State(server): State<Server>) -> Result<Response> {
    server
        .run(|state| serve(&state.web_dir, FsPath::new("index.html"), "no-cache"))
        .await
}

pub(crate) async fn asset(
    State(server): State<Server>,
    path: std::result::Result<Path<String>, PathRejection>,
) -> Result<Response> {
    let Path(path) = path.map_err(|_| Error::Missing)?;
    // Path has already decoded the URL once. Check each component before using it.
    let mut relative = FsPath::new("assets").to_owned();
    for component in path.split('/') {
        if component.is_empty()
            || component.contains(['\\', ':', '\0'])
            || component.ends_with(['.', ' '])
        {
            return Err(Error::Missing);
        }
        relative.push(component);
    }
    server
        .run(move |state| {
            serve(
                &state.web_dir,
                &relative,
                "public, max-age=31536000, immutable",
            )
        })
        .await
}

fn serve(web_dir: &FsPath, relative: &FsPath, cache: &'static str) -> Result<Response> {
    let root = fs::canonicalize(web_dir).map_err(static_io)?;
    let path = fs::canonicalize(root.join(relative)).map_err(static_io)?;
    // Canonical paths resolve symlinks and junctions before the containment check.
    if !path.starts_with(&root) || !fs::metadata(&path).map_err(static_io)?.is_file() {
        return Err(Error::Missing);
    }
    let file = File::open(&path).map_err(static_io)?;
    let size = file.metadata()?.len();
    Ok((
        [
            (header::CONTENT_TYPE, content_type(relative)),
            (header::CACHE_CONTROL, cache),
        ],
        [(header::CONTENT_LENGTH, size.to_string())],
        file_body(file),
    )
        .into_response())
}

fn static_io(error: io::Error) -> Error {
    match error.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::InvalidInput => Error::Missing,
        _ => error.into(),
    }
}

fn content_type(path: &FsPath) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("avif") => "image/avif",
        Some("gif") => "image/gif",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
