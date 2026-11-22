use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, de};
use sha2::{Digest, Sha256};
use tightlip_core::Secret32;
use zeroize::Zeroizing;

pub(crate) fn decode_secret(text: &str) -> Option<Secret32> {
    let mut bytes = Zeroizing::new([0; 33]);
    let len = URL_SAFE_NO_PAD.decode_slice(text, &mut *bytes).ok()?;
    if len != 32 {
        return None;
    }
    Some(Secret32::from_bytes(bytes[..32].try_into().ok()?))
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<Secret32> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (scheme, value) = values.next()?.to_str().ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || values.next().is_some() {
        return None;
    }
    decode_secret(value)
}

pub(crate) fn token_hash(token: &Secret32) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub(crate) fn deserialize_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Secret32, D::Error> {
    let text = Zeroizing::new(String::deserialize(deserializer)?);
    decode_secret(&text).ok_or_else(|| de::Error::custom("invalid credential"))
}
