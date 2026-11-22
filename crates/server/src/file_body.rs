use std::{
    fs::File,
    io::{self, Seek, SeekFrom},
};

use axum::body::Body;
use futures_util::stream;
use tokio::io::AsyncReadExt;

pub(crate) fn file_body(mut file: File, start: u64, len: u64) -> io::Result<Body> {
    if start != 0 {
        file.seek(SeekFrom::Start(start))?;
    }
    Ok(Body::from_stream(stream::try_unfold(
        tokio::fs::File::from_std(file).take(len),
        |mut file| async {
            let mut bytes = vec![0; 64 * 1024];
            let read = file.read(&mut bytes).await?;
            bytes.truncate(read);
            Ok::<_, io::Error>((read != 0).then_some((bytes, file)))
        },
    )))
}
