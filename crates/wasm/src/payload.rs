use serde::{Deserialize, Serialize};
use tightlip_core::manifest::{Login, Manifest, VERSION};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

// This projection is the only manifest data returned across the wasm boundary.
#[derive(Serialize)]
struct VisibleFile<'a> {
    name: &'a str,
    mime: &'a str,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    orientation: Option<u8>,
}

#[derive(Serialize)]
struct VisibleContent<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<&'a Login>,
    files: Vec<VisibleFile<'a>>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Content {
    note: Option<String>,
    login: Option<Login>,
}

pub(crate) fn from_content(content: Zeroizing<String>) -> Result<Manifest, Error> {
    let mut content: Content = serde_json::from_str(&content).map_err(|_| Error::Prepare)?;
    Ok(Manifest {
        v: VERSION,
        note: content.note.take(),
        login: content.login.take(),
        files: None,
    })
}

pub(crate) fn visible_content(manifest: &Manifest) -> Result<String, Error> {
    let content = VisibleContent {
        note: manifest.note.as_deref(),
        login: manifest.login.as_ref(),
        files: manifest
            .files
            .iter()
            .flatten()
            .map(|entry| VisibleFile {
                name: &entry.name,
                mime: &entry.mime,
                size: entry.size,
                orientation: entry.orientation,
            })
            .collect(),
    };
    serde_json::to_string(&content).map_err(|_| Error::Open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tightlip_core::{
        Secret32,
        manifest::{self, FileEntry},
    };

    #[test]
    fn the_web_projection_contains_orientation_and_omits_keys() {
        let mut draft = from_content(Zeroizing::new("{}".into())).unwrap();
        let id = [0; 16];
        let key = Secret32::generate().unwrap();
        assert!(manifest::seal_manifest(&key, &id, &draft).is_err());
        draft.files = Some(vec![FileEntry {
            name: "image.jpg".into(),
            mime: "image/jpeg".into(),
            size: 1,
            key: Secret32::generate().unwrap(),
            orientation: Some(6),
        }]);
        let encoded = manifest::seal_manifest(&key, &id, &draft).unwrap();
        let opened = manifest::open_manifest(&key, &id, &encoded, 1).unwrap();
        let visible: serde_json::Value =
            serde_json::from_str(&visible_content(&opened).unwrap()).unwrap();
        assert_eq!(visible["files"][0]["orientation"], 6);
        assert!(visible["files"][0].get("key").is_none());
    }
}
