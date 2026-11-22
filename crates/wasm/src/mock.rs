use subtle::ConstantTimeEq;
use tightlip_core::{Secret32, b64, oprf::ServerKey, share};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, decode_fixed, decode_secret};

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MockOprfKey(ServerKey);

#[wasm_bindgen]
impl MockOprfKey {
    pub fn generate() -> Result<MockOprfKey, JsValue> {
        Ok(Self(ServerKey::generate().map_err(|_| Error::Prepare)?))
    }

    pub fn blind_evaluate(&self, blinded: &str) -> Result<String, JsValue> {
        let blinded = decode_fixed::<32>(blinded)?;
        let evaluated = self
            .0
            .blind_evaluate(&blinded)
            .map_err(|_| Error::Encoding)?;
        Ok(b64::encode(&evaluated))
    }
}

#[wasm_bindgen]
pub fn mock_random_id() -> Result<String, JsValue> {
    Ok(b64::encode(
        &share::generate_share_id().map_err(|_| Error::Prepare)?,
    ))
}

#[wasm_bindgen]
pub fn mock_random_token() -> Result<String, JsValue> {
    let token = Secret32::generate().map_err(|_| Error::Prepare)?;
    Ok(b64::encode(token.as_bytes()))
}

#[wasm_bindgen]
pub fn mock_verify_access(tag: &str, verifier: &str) -> bool {
    let Ok(tag) = decode_secret(tag) else {
        return false;
    };
    let Ok(verifier) = decode_fixed(verifier) else {
        return false;
    };
    share::verify_access(&tag, &verifier)
}

#[wasm_bindgen]
pub fn mock_verify_owner(token: &str, verifier: &str) -> bool {
    let Ok(token) = decode_secret(token) else {
        return false;
    };
    let Ok(verifier) = decode_fixed(verifier) else {
        return false;
    };
    share::verify_owner(&token, &verifier)
}

#[wasm_bindgen]
pub fn mock_compare_tokens(first: &str, second: &str) -> bool {
    let Ok(first) = decode_secret(first) else {
        return false;
    };
    let Ok(second) = decode_secret(second) else {
        return false;
    };
    bool::from(first.as_bytes().ct_eq(second.as_bytes()))
}
