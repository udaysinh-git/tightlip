use std::{fs::File, io};

use axum::body::Body;
use futures_util::stream;
use tokio::io::AsyncReadExt;

pub(crate) fn file_body(file: File) -> Body {
    Body::from_stream(stream::try_unfold(
        tokio::fs::File::from_std(file),
        |mut file| async {
            let mut bytes = vec![0; 64 * 1024];
            let read = file.read(&mut bytes).await?;
            bytes.truncate(read);
            Ok::<_, io::Error>((read != 0).then_some((bytes, file)))
        },
    ))
}
