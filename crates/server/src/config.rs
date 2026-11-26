//! The limit variables are `TIGHTLIP_TTL_SECONDS` (min:max),
//! `TIGHTLIP_MAX_VIEWS`, `TIGHTLIP_ATTEMPTS` (password:passwordless offsets),
//! `TIGHTLIP_MANIFEST_BYTES`, `TIGHTLIP_FILES_PER_SHARE`,
//! `TIGHTLIP_TOTAL_CIPHERTEXT_BYTES`, `TIGHTLIP_STORAGE_BYTES`, `TIGHTLIP_PENDING_LIFETIME_SECONDS`,
//! and `TIGHTLIP_CREATES_PER_IP` (per hour).

use std::{env, fs::File, io::Read, path::PathBuf, str::FromStr};

use subtle::ConstantTimeEq;

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
    pub kek_id: u32,
    pub previous_kek: Option<(u32, Secret32)>,
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
        let kek = load_kek(&get)?;
        let kek_id = number(&get, "TIGHTLIP_KEK_ID", 1)?;
        if kek_id == 0 {
            return Err(ConfigError("TIGHTLIP_KEK_ID"));
        }
        let previous_kek = load_previous_kek(&get, kek_id)?;

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
            kek_id,
            previous_kek,
            trust_proxy: get("TIGHTLIP_TRUST_PROXY")?.as_deref() == Some("1"),
            limits,
        })
    }
}

fn load_kek(
    get: &impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
) -> Result<Secret32, ConfigError> {
    const FILE: &str = "TIGHTLIP_KEK_FILE";
    const ENV: &str = "TIGHTLIP_KEK";
    if let Some(path) = get(FILE)? {
        return read_kek_file(&path).ok_or(ConfigError(FILE));
    }
    value(get, ENV, |value| validate_kek(&Zeroizing::new(value)))?.ok_or(ConfigError(ENV))
}

fn load_previous_kek(
    get: &impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
    current_id: u32,
) -> Result<Option<(u32, Secret32)>, ConfigError> {
    const FILE: &str = "TIGHTLIP_KEK_PREVIOUS_FILE";
    const ID: &str = "TIGHTLIP_KEK_PREVIOUS_ID";
    let id = value(get, ID, |input| {
        input.parse::<u32>().ok().filter(|id| *id != current_id)
    })?;
    match (id, get(FILE)?) {
        (None, None) => Ok(None),
        (Some(id), Some(path)) => Ok(Some((id, read_kek_file(&path).ok_or(ConfigError(FILE))?))),
        (None, Some(_)) => Err(ConfigError(ID)),
        (Some(_), None) => Err(ConfigError(FILE)),
    }
}

fn validate_kek(text: &str) -> Option<Secret32> {
    let key = decode_secret(text)?;
    valid_kek(&key).then_some(key)
}

pub(crate) fn valid_kek(key: &Secret32) -> bool {
    let repeated = Zeroizing::new([key.as_bytes()[0]; 32]);
    !bool::from(key.as_bytes().ct_eq(&*repeated))
}

fn read_kek_file(path: &str) -> Option<Secret32> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o044 != 0 {
            return None;
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(46));
    file.take(46).read_to_end(&mut bytes).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    validate_kek(text)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tightlip_core::b64;

    #[test]
    fn rejects_repeated_bytes_and_prefers_the_key_file() {
        let repeated = b64::encode(&[0x77; 32]);
        assert!(validate_kek(&repeated).is_none());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek");
        let key = Secret32::generate().unwrap();
        std::fs::write(&path, format!("{}\n", b64::encode(key.as_bytes()))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let get = |name| match name {
            "TIGHTLIP_KEK_FILE" => Ok(Some(path.to_str().unwrap().to_owned())),
            _ => panic!("the file takes precedence"),
        };
        assert!(bool::from(
            load_kek(&get).unwrap().as_bytes().ct_eq(key.as_bytes())
        ));
        let get_previous = |name| match name {
            "TIGHTLIP_KEK_PREVIOUS_ID" => Ok(Some("0".to_owned())),
            "TIGHTLIP_KEK_PREVIOUS_FILE" => get("TIGHTLIP_KEK_FILE"),
            _ => Ok(None),
        };
        let (id, previous) = load_previous_kek(&get_previous, 1).unwrap().unwrap();
        assert_eq!(id, 0);
        assert!(bool::from(previous.as_bytes().ct_eq(key.as_bytes())));
        assert!(load_previous_kek(&get_previous, 0).is_err());
        assert!(
            load_previous_kek(
                &|name| get_previous(name)
                    .map(|value| { value.filter(|_| name == "TIGHTLIP_KEK_PREVIOUS_ID") }),
                1
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(load_kek(&get).is_err());
        }
    }
}
