use proptest::prelude::*;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::*;
use aead::{COMMITMENT_LEN, MAX_AAD_LEN, NONCE_LEN, OpenError, SealError, TAG_LEN};
use manifest::{FileEntry, Login, Manifest, VERSION};
use stream::{CHUNK_CIPHERTEXT_LEN, CHUNK_LEN, HEADER_LEN, PREFIX_LEN};

mod vectors;

fn sample_key() -> Secret32 {
    Secret32::from_bytes([1; 32])
}

#[test]
fn secrets_can_be_erased() {
    let mut key = sample_key();
    assert!(bool::from(key.as_bytes().ct_eq(&[1; 32])));
    key.zeroize();
    assert!(bool::from(key.as_bytes().ct_eq(&[0; 32])));

    let mut plaintext = pad::pad(b"test", 8).unwrap();
    plaintext.zeroize();
    assert!(plaintext.as_bytes().is_empty());
}

#[test]
fn base64url_is_canonical() {
    assert_eq!(b64::encode(&[255, 238]), "_-4");
    assert_eq!(b64::decode("_-4"), Ok(vec![255, 238]));
    assert_eq!(b64::decode(""), Ok(vec![]));
    for malformed in ["/+4", "_-4=", "_-5", "_-4\n", "A"] {
        assert_eq!(b64::decode(malformed), Err(b64::DecodeError));
    }
}

#[test]
fn share_link_keeps_the_secret_in_the_fragment() {
    let id = [2; 16];
    let secret = sample_key();
    let link = share::format_link("example.test", &id, &secret);
    let (route, fragment) = link.as_str().split_once('#').unwrap();
    let encoded_id = route.strip_prefix("https://example.test/s/").unwrap();
    assert_eq!(b64::decode(encoded_id), Ok(id.to_vec()));
    assert_eq!(b64::decode(fragment), Ok(secret.as_bytes().to_vec()));
}

#[test]
fn hkdf_rejects_output_beyond_the_rfc_limit() {
    let mut out = vec![0; 255 * 64 + 1];
    assert_eq!(
        kdf::derive(b"", b"input", b"", &mut out),
        Err(kdf::DeriveError)
    );
    assert!(kdf::derive(b"", b"input", b"", &mut out[..255 * 64]).is_ok());
    assert!(kdf::derive(b"", b"", b"", &mut []).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn seal_round_trip(
        key in any::<[u8; 32]>(),
        aad in proptest::collection::vec(any::<u8>(), 0..=MAX_AAD_LEN),
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let key = Secret32::from_bytes(key);
        let wire = aead::seal(&key, &aad, &plaintext).unwrap();
        let opened = aead::open(&key, &aad, &wire).unwrap();
        prop_assert_eq!(opened.as_bytes(), plaintext.as_slice());
    }

    #[test]
    fn stream_round_trips_across_chunk_boundaries(
        key in any::<[u8; 32]>(),
        aad in proptest::collection::vec(any::<u8>(), 0..160),
        pattern in any::<[u8; 32]>(),
        random_len in 0usize..=3 * CHUNK_LEN,
        encrypt_step in 1usize..=2 * CHUNK_LEN,
        decrypt_step in 1usize..=2 * CHUNK_CIPHERTEXT_LEN,
    ) {
        let key = Secret32::from_bytes(key);
        for len in [0, 1, 65535, 65536, 65537, 131072, random_len] {
            let plaintext: Vec<_> = pattern.iter().copied().cycle().take(len).collect();
            let wire = stream::stream_seal(&key, &aad, &plaintext).unwrap();
            let opened = stream::stream_open(&key, &aad, &wire).unwrap();
            prop_assert_eq!(opened.as_bytes(), plaintext.as_slice());
            prop_assert_eq!(wire.len(), HEADER_LEN + len + len.div_ceil(CHUNK_LEN).max(1) * TAG_LEN);

            let (header, mut enc) = stream::Encryptor::init(&key, &aad).unwrap();
            let mut dec = stream::Decryptor::init(&key, &aad, &header).unwrap();
            prop_assert!(enc.update(&[]).unwrap().is_empty());
            prop_assert!(dec.update(&[]).unwrap().as_bytes().is_empty());
            let mut body = Vec::new();
            for input in plaintext.chunks(encrypt_step) {
                body.extend(enc.update(input).unwrap());
            }
            body.extend(enc.finish().unwrap());
            let mut opened = Vec::new();
            for input in body.chunks(decrypt_step) {
                opened.extend_from_slice(dec.update(input).unwrap().as_bytes());
            }
            opened.extend_from_slice(dec.finish().unwrap().as_bytes());
            prop_assert_eq!(opened, plaintext);
        }
    }
}

#[test]
fn seal_checks_commitment_before_the_cipher() {
    let key = sample_key();
    let other_key = Secret32::from_bytes([2; 32]);
    let aad = b"test context";
    let wire = aead::seal(&key, aad, b"test payload").unwrap();

    aead::DECRYPT_CALLS.set(0);
    assert!(matches!(aead::open(&other_key, aad, &wire), Err(OpenError)));
    assert!(matches!(
        aead::open(&key, b"different context", &wire),
        Err(OpenError)
    ));
    assert_eq!(aead::DECRYPT_CALLS.get(), 0);

    let mut tampered = wire.clone();
    tampered[NONCE_LEN + COMMITMENT_LEN] ^= 1;
    assert!(matches!(aead::open(&key, aad, &tampered), Err(OpenError)));
    assert_eq!(aead::DECRYPT_CALLS.get(), 1);
    assert!(aead::open(&key, aad, &wire).is_ok());
    assert_eq!(aead::DECRYPT_CALLS.get(), 2);
}

#[test]
fn seal_rejects_tampered_regions_short_ciphertexts_and_excess_aad() {
    let key = sample_key();
    let aad = [0; MAX_AAD_LEN];
    let wire = aead::seal(&key, &aad, b"test payload").unwrap();
    for offset in [
        0,
        NONCE_LEN,
        NONCE_LEN + COMMITMENT_LEN,
        wire.len() - TAG_LEN,
    ] {
        let mut tampered = wire.clone();
        tampered[offset] ^= 1;
        assert!(matches!(aead::open(&key, &aad, &tampered), Err(OpenError)));
    }
    for len in [0, NONCE_LEN, NONCE_LEN + COMMITMENT_LEN + TAG_LEN - 1] {
        assert!(matches!(
            aead::open(&key, &aad, &wire[..len]),
            Err(OpenError)
        ));
    }
    let long_aad = [0; MAX_AAD_LEN + 1];
    assert_eq!(
        aead::seal(&key, &long_aad, b""),
        Err(SealError::InvalidInput)
    );
    assert!(matches!(aead::open(&key, &long_aad, &wire), Err(OpenError)));
}

#[test]
fn stream_rejects_header_and_chunk_tampering() {
    let key = sample_key();
    let aad = [3; MAX_AAD_LEN + 1];
    let data = vec![0; CHUNK_LEN * 2 + 1];
    let wire = stream::stream_seal(&key, &aad, &data).unwrap();
    assert_eq!(
        stream::stream_open(&key, &aad, &wire).unwrap().as_bytes(),
        data
    );
    let other_key = Secret32::from_bytes([2; 32]);
    assert!(matches!(
        stream::stream_open(&other_key, &aad, &wire),
        Err(OpenError)
    ));
    assert!(matches!(
        stream::stream_open(&key, b"wrong", &wire),
        Err(OpenError)
    ));
    assert!(matches!(
        stream::stream_open(&key, &aad, &wire[..HEADER_LEN - 1]),
        Err(OpenError)
    ));

    for offset in [
        0,
        PREFIX_LEN,
        HEADER_LEN,
        HEADER_LEN + CHUNK_CIPHERTEXT_LEN,
        wire.len() - TAG_LEN - 1,
        wire.len() - 1,
    ] {
        let mut tampered = wire.clone();
        tampered[offset] ^= 1;
        assert!(matches!(
            stream::stream_open(&key, &aad, &tampered),
            Err(OpenError)
        ));
    }
}

#[test]
fn stream_rejects_missing_reordered_duplicate_and_appended_chunks() {
    let key = sample_key();
    let aad = b"file";
    let wire = stream::stream_seal(&key, aad, &vec![7; CHUNK_LEN * 3]).unwrap();
    let (header, body) = wire.split_at(HEADER_LEN);
    let mut chunks = body.chunks_exact(CHUNK_CIPHERTEXT_LEN);
    let first = chunks.next().unwrap();
    let second = chunks.next().unwrap();
    let final_chunk = chunks.next().unwrap();

    for invalid in [
        [header, first].concat(),
        [header, first, second].concat(),
        [header, second, first, final_chunk].concat(),
        [header, first, first, second, final_chunk].concat(),
        [header, first, second, final_chunk, &[0]].concat(),
        wire[..wire.len() - 1].to_vec(),
    ] {
        assert!(matches!(
            stream::stream_open(&key, aad, &invalid),
            Err(OpenError)
        ));
    }

    let mut dec = stream::Decryptor::init(&key, aad, header).unwrap();
    assert!(dec.update(first).unwrap().as_bytes().is_empty());
    let mut bad_second = second.to_vec();
    bad_second[0] ^= 1;
    assert_eq!(dec.update(&bad_second).unwrap().as_bytes(), &[7; CHUNK_LEN]);
    assert!(matches!(dec.update(final_chunk), Err(OpenError)));
    assert!(matches!(dec.update(second), Err(OpenError)));
    assert!(matches!(dec.finish(), Err(OpenError)));
}

#[test]
fn padme_overhead_and_padding_syntax() {
    for len in 4097..=200_000 {
        let padded = pad::padme(len).unwrap();
        assert!(padded >= len && (padded - len) * 100 < len * 12);
    }
    assert_eq!(pad::padme(usize::MAX), Err(pad::PadError));
    let padded = pad::pad(b"x\0", 5).unwrap();
    assert_eq!(padded.as_bytes(), b"x\0\x80\0\0");
    assert_eq!(pad::unpad(padded.as_bytes()), Ok(b"x\0".as_slice()));
    assert_eq!(pad::unpad(&[0x80]), Ok(b"".as_slice()));
    assert!(matches!(pad::pad(b"x", 1), Err(pad::PadError)));
    assert!(matches!(pad::pad(b"x", usize::MAX), Err(pad::PadError)));
    for invalid in [b"".as_slice(), &[0, 0], &[0x80, 1, 0], &[0x81, 0]] {
        assert_eq!(pad::unpad(invalid), Err(pad::UnpadError));
    }
}

#[test]
fn oprf_rejects_invalid_points_and_lengths() {
    let key = oprf::ServerKey::generate().unwrap();
    let input = sample_key();
    let (blinded, state) = oprf::blind(&input).unwrap();
    let evaluated = key.blind_evaluate(&blinded).unwrap();
    assert_eq!(state.finalize(&evaluated).unwrap().as_bytes().len(), 64);
    let mut extended = blinded.to_vec();
    extended.push(0);
    for invalid in [&[0; 32], &[0xff; 32], &blinded[..31], &extended] {
        assert_eq!(
            key.blind_evaluate(invalid),
            Err(oprf::OprfError::InvalidInput)
        );
    }
    let mut extended = evaluated.to_vec();
    extended.push(0);
    for invalid in [&[0; 32], &[0xff; 32], &evaluated[..31], &extended] {
        let (_, state) = oprf::blind(&input).unwrap();
        assert!(matches!(
            state.finalize(invalid),
            Err(oprf::OprfError::InvalidInput)
        ));
    }
}

#[test]
fn share_roles_interoperate_through_wrapped_storage() {
    let link = Secret32::generate().unwrap();
    let owner = Secret32::generate().unwrap();
    let kek = Secret32::generate().unwrap();
    let id = share::generate_share_id().unwrap();

    let (blinded, creator) = share::start(&link, Some("test\u{ff21}")).unwrap();
    let server = oprf::ServerKey::generate().unwrap();
    let evaluated = server.blind_evaluate(&blinded).unwrap();
    let wrapped = share::wrap_oprf_key(&kek, &id, &server).unwrap();
    let creator_keys = creator.finish(&evaluated, &id).unwrap();
    let access = share::access_verifier(&creator_keys.access_tag);
    let owner_hash = share::owner_verifier(&owner);
    drop(server);

    let recipient_keys = {
        let (blinded, recipient) = share::start(&link, Some("testA")).unwrap();
        let restored = share::unwrap_oprf_key(&kek, &id, &wrapped).unwrap();
        let evaluated = restored.blind_evaluate(&blinded).unwrap();
        recipient.finish(&evaluated, &id).unwrap()
    };
    assert!(bool::from(
        recipient_keys
            .manifest_key
            .as_bytes()
            .ct_eq(creator_keys.manifest_key.as_bytes())
    ));
    assert!(share::verify_access(&recipient_keys.access_tag, &access));
    assert!(share::verify_owner(&owner, &owner_hash));
    assert!(!share::verify_access(&owner, &access));
    assert!(!share::verify_owner(
        &recipient_keys.access_tag,
        &owner_hash
    ));

    let manifest = Manifest {
        v: VERSION,
        note: Some("test note".into()),
        login: None,
        files: None,
    };
    let encrypted = manifest::seal_manifest(&creator_keys.manifest_key, &id, &manifest).unwrap();
    let decrypted =
        manifest::open_manifest(&recipient_keys.manifest_key, &id, &encrypted, 0).unwrap();
    assert_eq!(decrypted.note.as_deref(), Some("test note"));
}

#[test]
fn roots_are_bound_to_password_and_share_id() {
    let link = sample_key();
    let server = oprf::ServerKey::generate().unwrap();
    let derive_root = |password, id| {
        let material = share::Material::new(&link, password).unwrap();
        let input = material.oprf_input().unwrap();
        let (blinded, client) = oprf::blind(&input).unwrap();
        let evaluated = server.blind_evaluate(&blinded).unwrap();
        let output = client.finalize(&evaluated).unwrap();
        material.root(output.as_bytes(), &id).unwrap()
    };
    let first = derive_root(Some("test-one"), [1; 16]);
    let second = derive_root(Some("test-two"), [1; 16]);
    let other_share = derive_root(Some("test-one"), [2; 16]);
    let no_password = derive_root(None, [1; 16]);
    let empty_password = derive_root(Some(""), [1; 16]);
    assert!(!bool::from(first.as_bytes().ct_eq(second.as_bytes())));
    assert!(!bool::from(first.as_bytes().ct_eq(other_share.as_bytes())));
    assert!(!bool::from(
        no_password.as_bytes().ct_eq(empty_password.as_bytes())
    ));
}

#[test]
fn unwrap_rejects_wrong_key_wrong_share_and_invalid_scalar() {
    let kek = sample_key();
    let id = [1; 16];
    let server = oprf::ServerKey::generate().unwrap();
    let wrapped = share::wrap_oprf_key(&kek, &id, &server).unwrap();
    assert!(matches!(
        share::unwrap_oprf_key(&kek, &[2; 16], &wrapped),
        Err(OpenError)
    ));
    assert!(matches!(
        share::unwrap_oprf_key(&Secret32::from_bytes([2; 32]), &id, &wrapped),
        Err(OpenError)
    ));
    for invalid in [b"".as_slice(), &[0; 32], &[0xff; 32]] {
        let ciphertext =
            aead::seal(&kek, &share::share_aad(labels::OPRF_KEY, &id), invalid).unwrap();
        assert!(matches!(
            share::unwrap_oprf_key(&kek, &id, &ciphertext),
            Err(OpenError)
        ));
    }
}

#[test]
fn manifest_and_files_round_trip_with_bound_context() {
    let key = sample_key();
    let id = [5; 16];
    let data = b"test file\0\x80";
    let entry = FileEntry {
        name: "fixture.bin".into(),
        mime: "application/octet-stream".into(),
        size: data.len() as u64,
        orientation: None,
        key: Secret32::generate().unwrap(),
    };
    let mut login = Login::default();
    let _ = login.username.insert("test name".into());
    let original = Manifest {
        v: VERSION,
        note: None,
        login: Some(login),
        files: Some(vec![entry]),
    };
    let sealed = manifest::seal_manifest(&key, &id, &original).unwrap();
    assert_eq!(
        sealed.len(),
        NONCE_LEN + COMMITMENT_LEN + pad::MANIFEST_FLOOR + TAG_LEN
    );
    let parsed = manifest::open_manifest(&key, &id, &sealed, 1).unwrap();
    assert_eq!(
        parsed.login.as_ref().unwrap().username.as_deref(),
        Some("test name")
    );
    assert!(parsed.note.is_none());
    let entry = &parsed.files.as_ref().unwrap()[0];
    assert_eq!(entry.name, "fixture.bin");
    let file = manifest::seal_file(&id, 1, &original.files.as_ref().unwrap()[0], data).unwrap();
    assert_eq!(
        manifest::open_file(&id, 1, entry, &file)
            .unwrap()
            .as_bytes(),
        data
    );
    assert!(matches!(
        manifest::open_file(&id, 0, entry, &file),
        Err(OpenError)
    ));
    assert!(matches!(
        manifest::open_file(&[6; 16], 1, entry, &file),
        Err(OpenError)
    ));
    assert!(matches!(
        manifest::open_manifest(&key, &id, &sealed, 0),
        Err(OpenError)
    ));
    assert!(matches!(
        manifest::open_manifest(&key, &[6; 16], &sealed, 1),
        Err(OpenError)
    ));
}

#[test]
fn manifest_rejects_invalid_version_absence_encoding_and_padding() {
    let key = sample_key();
    let id = [5; 16];
    let missing = Manifest {
        v: VERSION,
        note: None,
        login: None,
        files: None,
    };
    assert!(matches!(
        manifest::seal_manifest(&key, &id, &missing),
        Err(manifest::PayloadSealError::InvalidPayload)
    ));
    let aad = share::share_aad(labels::MANIFEST, &id);
    for (json, count) in [
        (br#"{"v":2,"note":"test"}"#.as_slice(), 0),
        (br#"{"v":1}"#, 0),
        (
            br#"{"v":1,"files":[{"name":"test","mime":"text/plain","size":5,"key":"A==="}]}"#,
            1,
        ),
        (
            br#"{"v":1,"files":[{"name":"test","mime":"text/plain","size":5,"key":"AA"}]}"#,
            1,
        ),
        (b"\xff", 0),
    ] {
        let padded = pad::pad(json, 512).unwrap();
        let sealed = aead::seal(&key, &aad, padded.as_bytes()).unwrap();
        assert!(matches!(
            manifest::open_manifest(&key, &id, &sealed, count),
            Err(OpenError)
        ));
    }
    let unpadded = aead::seal(&key, &aad, br#"{"v":1,"note":"test"}"#).unwrap();
    assert!(matches!(
        manifest::open_manifest(&key, &id, &unpadded, 0),
        Err(OpenError)
    ));
}

#[test]
fn manifest_treats_empty_optional_sections_as_absent() {
    let key = sample_key();
    let id = [5; 16];
    let aad = share::share_aad(labels::MANIFEST, &id);
    for json in [
        br#"{"v":1,"note":""}"#.as_slice(),
        br#"{"v":1,"login":{}}"#,
        br#"{"v":1,"files":[]}"#,
        br#"{"v":1,"note":"","login":{},"files":[]}"#,
    ] {
        let manifest = serde_json::from_slice(json).unwrap();
        assert!(matches!(
            manifest::seal_manifest(&key, &id, &manifest),
            Err(manifest::PayloadSealError::InvalidPayload)
        ));
        let padded = pad::pad(json, pad::MANIFEST_FLOOR).unwrap();
        let ciphertext = aead::seal(&key, &aad, padded.as_bytes()).unwrap();
        assert!(matches!(
            manifest::open_manifest(&key, &id, &ciphertext, 0),
            Err(OpenError)
        ));
    }
    let manifest = Manifest {
        v: VERSION,
        note: Some("content".into()),
        login: Some(Login::default()),
        files: Some(Vec::new()),
    };
    let ciphertext = manifest::seal_manifest(&key, &id, &manifest).unwrap();
    assert!(manifest::open_manifest(&key, &id, &ciphertext, 0).is_ok());
}

#[test]
fn file_open_enforces_minimum_true_size_and_truncates() {
    let id = [5; 16];
    let mut entry = FileEntry {
        name: "fixture.bin".into(),
        mime: "application/octet-stream".into(),
        size: 3,
        orientation: None,
        key: sample_key(),
    };
    let wire = manifest::seal_file(&id, 0, &entry, b"abc").unwrap();
    entry.size = 4;
    assert!(matches!(
        manifest::seal_file(&id, 0, &entry, b"abc"),
        Err(manifest::PayloadSealError::InvalidPayload)
    ));
    assert!(matches!(
        manifest::open_file(&id, 0, &entry, &wire),
        Err(OpenError)
    ));
    entry.size = 2;
    assert_eq!(
        manifest::open_file(&id, 0, &entry, &wire)
            .unwrap()
            .as_bytes(),
        b"ab"
    );
    entry.size = 0;
    let empty = manifest::seal_file(&id, 0, &entry, b"").unwrap();
    assert!(
        manifest::open_file(&id, 0, &entry, &empty)
            .unwrap()
            .as_bytes()
            .is_empty()
    );
    let malformed = stream::stream_seal(&entry.key, &manifest::file_aad(&id, 0), b"abc\0").unwrap();
    assert!(matches!(
        manifest::open_file(&id, 0, &entry, &malformed),
        Err(OpenError)
    ));
}
