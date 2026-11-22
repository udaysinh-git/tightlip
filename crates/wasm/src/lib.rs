#![forbid(unsafe_code)]

use js_sys::Uint8Array;
use thiserror::Error;
use tightlip_core::{
    Secret32, b64,
    share::{self, ShareId},
    stream::HEADER_LEN,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod image;
mod payload;

#[cfg(feature = "dev-mock")]
mod mock;

#[derive(Debug, Error)]
enum Error {
    #[error("Invalid link or response data.")]
    Encoding,
    #[error("Could not prepare the share. Try again.")]
    Prepare,
    #[error("Could not decrypt the share.")]
    Open,
    #[error("Could not read image metadata. Choose another image.")]
    Image,
}

impl From<Error> for JsValue {
    fn from(value: Error) -> Self {
        js_sys::Error::new(&value.to_string()).into()
    }
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], Error> {
    b64::decode(encoded)
        .map_err(|_| Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)
}

fn parse_id(path: &str) -> Result<ShareId, Error> {
    decode_fixed(path.strip_prefix("/s/").ok_or(Error::Encoding)?)
}

fn decode_secret(encoded: &str) -> Result<Secret32, Error> {
    let bytes = Zeroizing::new(b64::decode(encoded).map_err(|_| Error::Encoding)?);
    let fixed = bytes.as_slice().try_into().map_err(|_| Error::Encoding)?;
    Ok(Secret32::from_bytes(fixed))
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LinkSecret(Secret32);

#[wasm_bindgen]
impl LinkSecret {
    pub fn generate() -> Result<LinkSecret, JsValue> {
        Ok(Self(Secret32::generate().map_err(|_| Error::Prepare)?))
    }

    pub fn parse(path: &str, fragment: String) -> Result<LinkSecret, JsValue> {
        let fragment = Zeroizing::new(fragment);
        parse_id(path)?;
        Ok(Self(decode_secret(&fragment)?))
    }

    pub fn format(&self, authority: &str, id: &str) -> Result<String, JsValue> {
        let id = decode_fixed(id)?;
        Ok(share::format_link(authority, &id, &self.0)
            .as_str()
            .to_owned())
    }

    pub fn start(&self, password: Option<String>) -> Result<Exchange, JsValue> {
        let password = Zeroizing::new(password);
        let (blinded, state) =
            share::start(&self.0, password.as_deref()).map_err(|_| Error::Prepare)?;
        Ok(Exchange {
            blinded,
            state: Some(state),
        })
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OwnerToken(Secret32);

#[wasm_bindgen]
impl OwnerToken {
    pub fn generate() -> Result<OwnerToken, JsValue> {
        Ok(Self(Secret32::generate().map_err(|_| Error::Prepare)?))
    }

    pub fn verifier(&self) -> String {
        b64::encode(&share::owner_verifier(&self.0))
    }

    pub fn bearer(&self) -> String {
        b64::encode(self.0.as_bytes())
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Exchange {
    blinded: [u8; 32],
    state: Option<share::ClientState>,
}

#[wasm_bindgen]
impl Exchange {
    pub fn blinded(&self) -> String {
        b64::encode(&self.blinded)
    }

    pub fn finish(mut self, evaluated: &str, id: &str) -> Result<ShareSession, JsValue> {
        let id = decode_fixed(id)?;
        let evaluated = decode_fixed::<32>(evaluated)?;
        let keys = self
            .state
            .take()
            .ok_or(Error::Prepare)?
            .finish(&evaluated, &id)
            .map_err(|_| Error::Prepare)?;
        Ok(ShareSession { id, keys })
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareSession {
    id: ShareId,
    keys: share::ShareKeys,
}

#[wasm_bindgen]
impl ShareSession {
    pub fn access_tag(&self) -> String {
        b64::encode(self.keys.access_tag.as_bytes())
    }

    pub fn access_verifier(&self) -> String {
        b64::encode(&share::access_verifier(&self.keys.access_tag))
    }

    pub fn draft(&self, content: String) -> Result<Draft, JsValue> {
        Ok(Draft(payload::Manifest::from_content(Zeroizing::new(
            content,
        ))?))
    }

    pub fn seal_manifest(&self, draft: &Draft) -> Result<Vec<u8>, JsValue> {
        Ok(draft.0.seal(&self.keys.manifest_key, &self.id)?)
    }

    pub fn open_manifest(&self, encoded: &str, count: usize) -> Result<OpenedManifest, JsValue> {
        let ciphertext = b64::decode(encoded).map_err(|_| Error::Open)?;
        let manifest =
            payload::Manifest::open(&self.keys.manifest_key, &self.id, &ciphertext, count)?;
        Ok(OpenedManifest {
            id: self.id,
            manifest,
        })
    }

    pub fn seal_file_init(
        &self,
        draft: &mut Draft,
        name: String,
        mime: String,
        size: usize,
        orientation: Option<u8>,
    ) -> Result<FileSeal, JsValue> {
        Ok(FileSeal(draft.0.add_file(
            &self.id,
            name,
            mime,
            size,
            orientation,
        )?))
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Draft(payload::Manifest);

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileSeal(payload::FileSeal);

#[wasm_bindgen]
impl FileSeal {
    pub fn header(&self) -> Vec<u8> {
        self.0.header().to_vec()
    }

    pub fn update(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.update(&Zeroizing::new(bytes))?)
    }

    pub fn finish(mut self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.finish()?)
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpenedManifest {
    id: ShareId,
    manifest: payload::Manifest,
}

#[wasm_bindgen]
impl OpenedManifest {
    pub fn visible_content(&self) -> Result<String, JsValue> {
        Ok(self.manifest.visible_content()?)
    }

    pub fn decrypt_file_init(&self, index: u32, header: &[u8]) -> Result<FileOpen, JsValue> {
        Ok(FileOpen(self.manifest.open_file(&self.id, index, header)?))
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileOpen(payload::FileOpen);

#[wasm_bindgen]
impl FileOpen {
    pub fn update(&mut self, bytes: &[u8]) -> Result<Uint8Array, JsValue> {
        Ok(self
            .0
            .update(bytes, |plaintext| Uint8Array::from(plaintext))?)
    }

    pub fn finish(mut self) -> Result<Uint8Array, JsValue> {
        Ok(self.0.finish(|plaintext| Uint8Array::from(plaintext))?)
    }
}

#[wasm_bindgen]
pub fn file_header_length() -> usize {
    HEADER_LEN
}

#[wasm_bindgen]
pub fn generate_password() -> Result<String, JsValue> {
    let random = Secret32::generate().map_err(|_| Error::Prepare)?;
    Ok(b64::encode(random.as_bytes()))
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ScrubbedImage {
    bytes: Zeroizing<Vec<u8>>,
    orientation: Option<u8>,
}

#[wasm_bindgen]
impl ScrubbedImage {
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(self.bytes.as_slice())
    }

    pub fn orientation(&self) -> Option<u8> {
        self.orientation
    }
}

#[wasm_bindgen]
pub fn strip_image_metadata(bytes: Vec<u8>, mime: &str) -> Result<ScrubbedImage, JsValue> {
    let bytes = Zeroizing::new(bytes);
    let (output, orientation) = image::strip(&bytes, mime)?;
    Ok(ScrubbedImage {
        bytes: output,
        orientation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_path_and_fragment_have_exact_lengths() {
        let id = [0; 16];
        let secret = Secret32::from_bytes([0; 32]);
        let link = share::format_link("example.test", &id, &secret);
        let path_and_fragment = link.as_str().strip_prefix("https://example.test").unwrap();
        let (path, fragment) = path_and_fragment.split_once('#').unwrap();
        assert_eq!(parse_id(path).unwrap(), id);
        assert_eq!(
            decode_secret(fragment).unwrap().as_bytes(),
            secret.as_bytes()
        );
        assert!(parse_id(&format!("{path}=")).is_err());
        assert!(decode_secret("short").is_err());
    }

    #[test]
    fn empty_password_and_no_password_produce_distinct_verifiers() {
        let link = LinkSecret(Secret32::from_bytes([3; 32]));
        let server = tightlip_core::oprf::ServerKey::generate().unwrap();
        let id = b64::encode(&[4; 16]);
        let derive = |password| {
            let exchange = link.start(password).unwrap();
            let blinded = b64::decode(&exchange.blinded()).unwrap();
            let evaluated = b64::encode(&server.blind_evaluate(&blinded).unwrap());
            exchange.finish(&evaluated, &id).unwrap().access_verifier()
        };
        let without = derive(None);
        let empty = derive(Some(String::new()));
        assert_ne!(without, empty);
        assert_eq!(empty, derive(Some(String::new())));
    }
}
