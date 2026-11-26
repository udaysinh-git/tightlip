//! Client key derivation and server key storage for a link share.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    RandomError, Secret32,
    aead::{self, OpenError, SealError},
    b64,
    kdf::{self, DeriveError},
    labels,
    oprf::{self, OprfError, ServerKey},
    secret::fill_random,
};

pub type ShareId = [u8; 16];
pub type Verifier = [u8; 32];

/// An HTTPS share URL whose fragment contains the link secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareLink(String);

impl ShareLink {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

const PASSWORD_MEMORY_KIB: u32 = 65536;
const PASSWORD_ITERATIONS: u32 = 3;
const PASSWORD_PARALLELISM: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShareError {
    #[error(transparent)]
    Derive(#[from] DeriveError),
    #[error("password derivation failed")]
    Password,
    #[error(transparent)]
    Oprf(#[from] OprfError),
}

/// A recipient or creator's pending OPRF exchange.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientState {
    material: Material,
    oprf: oprf::ClientState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareKeys {
    pub manifest_key: Secret32,
    pub access_tag: Secret32,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Material {
    ikm: [u8; 64],
    flag: u8,
}

pub fn generate_share_id() -> Result<ShareId, RandomError> {
    let mut id = [0; 16];
    fill_random(&mut id)?;
    Ok(id)
}

/// Formats a link using the caller's configured HTTPS authority, without a path or scheme.
pub fn format_link(authority: &str, share_id: &ShareId, link_secret: &Secret32) -> ShareLink {
    let id = b64::encode(share_id);
    let fragment = Zeroizing::new(b64::encode(link_secret.as_bytes()));
    ShareLink(["https://", authority, "/s/", &id, "#", &fragment].concat())
}

/// `None` selects the passwordless path. `Some("")` is a password.
pub fn start(
    link_secret: &Secret32,
    password: Option<&str>,
) -> Result<([u8; 32], ClientState), ShareError> {
    let material = Material::new(link_secret, password)?;
    let input = material.oprf_input()?;
    let (blinded, oprf) = oprf::blind(&input)?;
    Ok((blinded, ClientState { material, oprf }))
}

impl ClientState {
    pub fn finish(self, evaluated: &[u8], share_id: &ShareId) -> Result<ShareKeys, ShareError> {
        let output = self.oprf.finalize_ref(evaluated)?;
        let root = self.material.root(output.as_bytes(), share_id)?;
        Ok(keys_from_root(&root)?)
    }
}

impl Material {
    pub(crate) fn new(link_secret: &Secret32, password: Option<&str>) -> Result<Self, ShareError> {
        let mut material = Self {
            ikm: [0; 64],
            flag: u8::from(password.is_some()),
        };
        let (link, password_key) = material.ikm.split_at_mut(32);
        link.copy_from_slice(link_secret.as_bytes());
        if let Some(password) = password {
            let normalized = Zeroizing::new(password.nfkc().collect::<String>());
            let salt = password_salt(link_secret)?;
            let params = Params::new(
                PASSWORD_MEMORY_KIB,
                PASSWORD_ITERATIONS,
                PASSWORD_PARALLELISM,
                Some(32),
            )
            .map_err(|_| ShareError::Password)?;
            let mut blocks = Zeroizing::new(vec![Block::default(); params.block_count()]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into_with_memory(
                    normalized.as_bytes(),
                    &*salt,
                    password_key,
                    blocks.as_mut_slice(),
                )
                .map_err(|_| ShareError::Password)?;
        }
        Ok(material)
    }

    fn ikm(&self) -> &[u8] {
        &self.ikm[..32 + 32 * usize::from(self.flag)]
    }

    pub(crate) fn oprf_input(&self) -> Result<Secret32, DeriveError> {
        derive_secret(b"", self.ikm(), &[labels::OPRF_INPUT, &[self.flag]])
    }

    pub(crate) fn root(
        &self,
        oprf_output: &[u8; 64],
        id: &ShareId,
    ) -> Result<Secret32, DeriveError> {
        derive_secret(oprf_output, self.ikm(), &[labels::ROOT, &[self.flag], id])
    }
}

pub(crate) fn password_salt(link_secret: &Secret32) -> Result<Zeroizing<[u8; 16]>, DeriveError> {
    let mut salt = Zeroizing::new([0; 16]);
    kdf::derive(b"", link_secret.as_bytes(), labels::PW_SALT, &mut *salt)?;
    Ok(salt)
}

pub(crate) fn keys_from_root(root: &Secret32) -> Result<ShareKeys, DeriveError> {
    Ok(ShareKeys {
        manifest_key: derive_secret(b"", root.as_bytes(), &[labels::MANIFEST_KEY])?,
        access_tag: derive_secret(b"", root.as_bytes(), &[labels::ACCESS])?,
    })
}

fn derive_secret(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Result<Secret32, DeriveError> {
    let mut bytes = Zeroizing::new([0; 32]);
    kdf::expand(salt, ikm, info, &mut *bytes)?;
    Ok(Secret32::from_bytes(*bytes))
}

pub fn eval_tag(link_secret: &Secret32) -> Result<Secret32, DeriveError> {
    derive_secret(b"", link_secret.as_bytes(), &[labels::EVAL_AUTH])
}

pub fn eval_verifier(tag: &Secret32) -> Verifier {
    verifier(labels::EVAL_VERIFIER, tag)
}

pub fn verify_eval(tag: &Secret32, expected: &Verifier) -> bool {
    bool::from(eval_verifier(tag).ct_eq(expected))
}

pub fn access_verifier(access_tag: &Secret32) -> Verifier {
    verifier(labels::ACCESS_VERIFIER, access_tag)
}

pub fn owner_verifier(owner_token: &Secret32) -> Verifier {
    verifier(labels::OWNER_VERIFIER, owner_token)
}

pub fn verify_access(access_tag: &Secret32, expected: &Verifier) -> bool {
    bool::from(access_verifier(access_tag).ct_eq(expected))
}

pub fn verify_owner(owner_token: &Secret32, expected: &Verifier) -> bool {
    bool::from(owner_verifier(owner_token).ct_eq(expected))
}

fn verifier(label: &[u8], secret: &Secret32) -> Verifier {
    Sha256::new()
        .chain_update(label)
        .chain_update(secret.as_bytes())
        .finalize()
        .into()
}

pub fn wrap_oprf_key(
    kek: &Secret32,
    kek_id: u32,
    share_id: &ShareId,
    key: &ServerKey,
) -> Result<Vec<u8>, SealError> {
    let mut aad = share_aad(labels::OPRF_KEY, share_id);
    let mut wrapped = Vec::new();
    if kek_id != 0 {
        let prefix = kek_id.to_be_bytes();
        aad.extend_from_slice(&prefix);
        wrapped.extend_from_slice(&prefix);
    }
    wrapped.extend(aead::seal(kek, &aad, key.secret().as_bytes())?);
    Ok(wrapped)
}

const LEGACY_WRAP_LEN: usize = aead::NONCE_LEN + aead::COMMITMENT_LEN + 32 + aead::TAG_LEN;

pub fn wrapped_kek_id(wrapped: &[u8]) -> Result<u32, OpenError> {
    match wrapped.len() {
        LEGACY_WRAP_LEN => Ok(0),
        len if len == LEGACY_WRAP_LEN + size_of::<u32>() => {
            let (prefix, _) = wrapped.split_first_chunk().ok_or(OpenError)?;
            let id = u32::from_be_bytes(*prefix);
            if id == 0 { Err(OpenError) } else { Ok(id) }
        }
        _ => Err(OpenError),
    }
}

pub fn unwrap_oprf_key(
    kek: &Secret32,
    kek_id: u32,
    share_id: &ShareId,
    wrapped: &[u8],
) -> Result<ServerKey, OpenError> {
    if wrapped_kek_id(wrapped)? != kek_id {
        return Err(OpenError);
    }
    let mut aad = share_aad(labels::OPRF_KEY, share_id);
    let wrapped = if kek_id == 0 {
        wrapped
    } else {
        let (prefix, ciphertext) = wrapped.split_first_chunk::<4>().ok_or(OpenError)?;
        aad.extend_from_slice(prefix);
        ciphertext
    };
    let key = aead::open(kek, &aad, wrapped)?;
    let bytes = key.as_bytes().try_into().map_err(|_| OpenError)?;
    ServerKey::from_secret(Secret32::from_bytes(bytes)).map_err(|_| OpenError)
}

pub(crate) fn share_aad(label: &[u8], share_id: &ShareId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(label.len() + share_id.len());
    aad.extend_from_slice(label);
    aad.extend_from_slice(share_id);
    aad
}
