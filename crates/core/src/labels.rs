//! Domain separation and suite identifiers from the protocol specification.

pub const SUITE: &str = "tightlip-v1";
pub const AEAD: &[u8] = b"tightlip/v1/aead";
pub const STREAM: &[u8] = b"tightlip/v1/stream";
pub const PW_SALT: &[u8] = b"tightlip/v1/pw-salt";
pub const OPRF_INPUT: &[u8] = b"tightlip/v1/oprf-input";
pub const ROOT: &[u8] = b"tightlip/v1/root";
pub const MANIFEST_KEY: &[u8] = b"tightlip/v1/manifest-key";
pub const EVAL_AUTH: &[u8] = b"tightlip/v1/eval-auth";
pub const EVAL_VERIFIER: &[u8] = b"tightlip/v1/eval-verifier";
pub const ACCESS: &[u8] = b"tightlip/v1/access";
pub const ACCESS_VERIFIER: &[u8] = b"tightlip/v1/access-verifier";
pub const OWNER_VERIFIER: &[u8] = b"tightlip/v1/owner-verifier";
pub const MANIFEST: &[u8] = b"tightlip/v1/manifest";
pub const FILE: &[u8] = b"tightlip/v1/file";
pub const OPRF_KEY: &[u8] = b"tightlip/v1/oprf-key";
