//! The limit variables are `TIGHTLIP_TTL_SECONDS` (min:max),
//! `TIGHTLIP_MAX_VIEWS`, `TIGHTLIP_ATTEMPTS` (password:passwordless offsets),
//! `TIGHTLIP_MANIFEST_BYTES`, `TIGHTLIP_FILES_PER_SHARE`,
//! `TIGHTLIP_TOTAL_CIPHERTEXT_BYTES`, `TIGHTLIP_STORAGE_BYTES`, `TIGHTLIP_PENDING_LIFETIME_SECONDS`,
//! and `TIGHTLIP_CREATES_PER_IP` (per hour).

use std::{env, path::PathBuf, str::FromStr};

use thiserror::Error;
use tightlip_core::Secret32;
use zeroize::Zeroizing;

use crate::credentials::decode_secret;

#[derive(Debug, Error)]
#[error("missing or invalid environment variable {0}")]
pub struct ConfigError(&'static str);

pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
    pub web_dir: PathBuf,
    pub public_url: Option<String>,
    pub kek: Secret32,
    pub trust_proxy: bool,
    pub limits: Limits,
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub min_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
    pub max_views: u32,
    pub password_attempts_extra: u32,
    pub passwordless_attempts_extra: u32,
    pub manifest_bytes: u32,
    pub files_per_share: u32,
    pub total_ciphertext_bytes: u64,
    pub storage_bytes: u64,
    pub pending_lifetime_seconds: u32,
    pub creates_per_ip: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            min_ttl_seconds: 300,
            max_ttl_seconds: 2_592_000,
            max_views: 100,
            password_attempts_extra: 5,
            passwordless_attempts_extra: 3,
            manifest_bytes: 256_000,
            files_per_share: 20,
            total_ciphertext_bytes: 25_000_000,
            storage_bytes: 5_000_000_000,
            pending_lifetime_seconds: 900,
            creates_per_ip: 30,
        }
    }
}

impl Config {
    pub fn port_from_env() -> Result<u16, ConfigError> {
        number(&read_env, "PORT", 8080)
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let get = read_env;
        let kek = value(&get, "TIGHTLIP_KEK", |value| {
            decode_secret(&Zeroizing::new(value))
        })?
        .ok_or(ConfigError("TIGHTLIP_KEK"))?;

        let mut limits = Limits::default();
        // Range and attempt offsets are pairs, so each table row has one setting.
        (limits.min_ttl_seconds, limits.max_ttl_seconds) =
            value(&get, "TIGHTLIP_TTL_SECONDS", |value| {
                let (min, max) = pair(&value)?;
                (min > 0 && min <= max).then_some((min, max))
            })?
            .unwrap_or((limits.min_ttl_seconds, limits.max_ttl_seconds));
        (
            limits.password_attempts_extra,
            limits.passwordless_attempts_extra,
        ) = value(&get, "TIGHTLIP_ATTEMPTS", |value| pair(&value))?.unwrap_or((
            limits.password_attempts_extra,
            limits.passwordless_attempts_extra,
        ));
        limits.max_views = number(&get, "TIGHTLIP_MAX_VIEWS", limits.max_views)?;
        if limits.max_views == 0 {
            return Err(ConfigError("TIGHTLIP_MAX_VIEWS"));
        }
        if limits
            .max_views
            .checked_add(
                limits
                    .password_attempts_extra
                    .max(limits.passwordless_attempts_extra),
            )
            .is_none()
        {
            return Err(ConfigError("TIGHTLIP_ATTEMPTS"));
        }
        limits.manifest_bytes = number(&get, "TIGHTLIP_MANIFEST_BYTES", limits.manifest_bytes)?;
        limits.files_per_share = number(&get, "TIGHTLIP_FILES_PER_SHARE", limits.files_per_share)?;
        limits.total_ciphertext_bytes = number(
            &get,
            "TIGHTLIP_TOTAL_CIPHERTEXT_BYTES",
            limits.total_ciphertext_bytes,
        )?;
        if i64::try_from(limits.total_ciphertext_bytes).is_err() {
            return Err(ConfigError("TIGHTLIP_TOTAL_CIPHERTEXT_BYTES"));
        }
        limits.storage_bytes = number(&get, "TIGHTLIP_STORAGE_BYTES", limits.storage_bytes)?;
        if i64::try_from(limits.storage_bytes).is_err() {
            return Err(ConfigError("TIGHTLIP_STORAGE_BYTES"));
        }
        limits.pending_lifetime_seconds = number(
            &get,
            "TIGHTLIP_PENDING_LIFETIME_SECONDS",
            limits.pending_lifetime_seconds,
        )?;
        limits.creates_per_ip = number(&get, "TIGHTLIP_CREATES_PER_IP", limits.creates_per_ip)?;

        Ok(Self {
            port: Self::port_from_env()?,
            data_dir: get("TIGHTLIP_DATA_DIR")?.map_or_else(|| "./data".into(), PathBuf::from),
            web_dir: get("TIGHTLIP_WEB_DIR")?.map_or_else(|| "./web/dist".into(), PathBuf::from),
            public_url: get("TIGHTLIP_PUBLIC_URL")?,
            kek,
            trust_proxy: get("TIGHTLIP_TRUST_PROXY")?.as_deref() == Some("1"),
            limits,
        })
    }
}

fn read_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError(name)),
    }
}

fn pair(value: &str) -> Option<(u32, u32)> {
    let (first, second) = value.split_once(':')?;
    Some((first.parse().ok()?, second.parse().ok()?))
}

fn value<T>(
    get: &impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
    parse: impl FnOnce(String) -> Option<T>,
) -> Result<Option<T>, ConfigError> {
    get(name)?
        .map(|input| parse(input).ok_or(ConfigError(name)))
        .transpose()
}

fn number<T: FromStr>(
    get: &impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    Ok(value(get, name, |input| input.parse().ok())?.unwrap_or(default))
}
