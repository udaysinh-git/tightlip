use std::{fs, path::PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

type VectorSet = (&'static str, fn() -> Value);

const VECTOR_SETS: &[VectorSet] = &[
    ("kdf", kdf_vectors),
    ("eval_auth", eval_auth_vector),
    ("seal", seal_vectors),
    ("stream_seal", stream_vectors),
    ("padme", padme_vectors),
    ("share", share_vectors),
    ("oprf_rfc9497", rfc_oprf_vector),
];

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

fn load(name: &str) -> Value {
    let path = vector_dir().join(format!("{name}.json"));
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
#[ignore = "writes the section 9 fixtures to docs/vectors"]
fn write_known_answer_vectors() {
    let directory = vector_dir();
    fs::create_dir_all(&directory).unwrap();
    for (name, generate) in VECTOR_SETS {
        let rendered = serde_json::to_string_pretty(&generate()).unwrap();
        fs::write(
            directory.join(format!("{name}.json")),
            format!("{rendered}\n"),
        )
        .unwrap();
    }
}

#[test]
fn kdf_known_answers() {
    assert_eq!(load("kdf"), kdf_vectors());
}

#[test]
fn eval_auth_known_answer() {
    assert_eq!(load("eval_auth"), eval_auth_vector());
    let secret = Secret32::from_bytes(bytes::<32>(0));
    let first = share::eval_tag(&secret, &bytes::<16>(32)).unwrap();
    let second = share::eval_tag(&secret, &bytes::<16>(33)).unwrap();
    let expected = share::eval_verifier(&first);
    assert!(share::verify_eval(&first, &expected));
    assert!(!share::verify_eval(&second, &expected));
}

fn eval_auth_vector() -> Value {
    let link_secret = Secret32::from_bytes(bytes::<32>(0));
    let share_id = bytes::<16>(32);
    let tag = share::eval_tag(&link_secret, &share_id).unwrap();
    json!({
        "suite": labels::SUITE,
        "link_secret": b64::encode(link_secret.as_bytes()),
        "share_id": b64::encode(&share_id),
        "eval_tag": b64::encode(tag.as_bytes()),
        "eval_verifier": b64::encode(&share::eval_verifier(&tag)),
    })
}

#[test]
fn seal_known_answers() {
    assert_eq!(load("seal"), seal_vectors());
}

#[test]
fn stream_seal_known_answers() {
    assert_eq!(load("stream_seal"), stream_vectors());
}

#[test]
fn padme_known_answers() {
    assert_eq!(load("padme"), padme_vectors());
    let expected: [(usize, usize); 8] = [
        (0, 0),
        (1, 1),
        (2, 2),
        (17, 18),
        (33, 36),
        (65, 72),
        (129, 144),
        (4097, 4352),
    ];
    for (len, padded) in expected {
        assert_eq!(pad::padme(len), Ok(padded));
    }
}

#[test]
fn link_schedule_known_answers() {
    assert_eq!(load("share"), share_vectors());
}

#[test]
fn published_oprf_known_answer() {
    let vector = load("oprf_rfc9497");
    let get = |name: &str| b64::decode(vector[name].as_str().unwrap()).unwrap();
    let server =
        oprf::ServerKey::from_secret(Secret32::from_bytes(get("oprf_key").try_into().unwrap()))
            .unwrap();
    let (blinded, state) = oprf::blind_with_scalar(
        &get("input"),
        Secret32::from_bytes(get("blind").try_into().unwrap()),
    )
    .unwrap();
    assert_eq!(blinded.as_slice(), get("blinded"));
    let evaluated = server.blind_evaluate(&blinded).unwrap();
    assert_eq!(evaluated.as_slice(), get("evaluated"));
    assert_eq!(
        state.finalize(&evaluated).unwrap().as_bytes().as_slice(),
        get("output")
    );
}

fn bytes<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start + u8::try_from(i).unwrap())
}

fn scalar(value: u8) -> Secret32 {
    let mut bytes = [0; 32];
    bytes[0] = value;
    Secret32::from_bytes(bytes)
}

fn kdf_vectors() -> Value {
    let ikm = bytes::<32>(0);
    let aad = [0, 255, 1];
    let aad_len = u32::try_from(aad.len()).unwrap().to_be_bytes();
    let id = bytes::<16>(32);
    let oprf_out = bytes::<64>(64);
    let nonce = bytes::<NONCE_LEN>(32);
    let stream_prefix = bytes::<PREFIX_LEN>(64);
    let mut vectors = Vec::new();
    let mut add = |label: &[u8], salt: &[u8], suffix: &[&[u8]], len: usize| {
        let info = [label, suffix.concat().as_slice()].concat();
        let mut okm = vec![0; len];
        kdf::derive(salt, &ikm, &info, &mut okm).unwrap();
        vectors.push(json!({
            "label": std::str::from_utf8(label).unwrap(),
            "salt": b64::encode(salt),
            "ikm": b64::encode(&ikm),
            "info": b64::encode(&info),
            "output": b64::encode(&okm),
        }));
    };
    add(labels::AEAD, &nonce, &[&aad_len, &aad], 64);
    add(labels::STREAM, &stream_prefix, &[&aad_len, &aad], 64);
    add(labels::PW_SALT, b"", &[], 16);
    for flag in [0, 1] {
        add(labels::OPRF_INPUT, b"", &[&[flag]], 32);
        add(labels::ROOT, &oprf_out, &[&[flag], &id], 32);
    }
    add(labels::MANIFEST_KEY, b"", &[], 32);
    add(labels::ACCESS, b"", &[], 32);
    json!({"suite": labels::SUITE, "vectors": vectors})
}

fn seal_vectors() -> Value {
    let key = Secret32::from_bytes(bytes::<32>(0));
    let mut vectors = Vec::new();
    for (nonce, aad, plaintext) in [
        (bytes::<NONCE_LEN>(32), b"".as_slice(), b"".as_slice()),
        (bytes::<NONCE_LEN>(64), &[0, 255, 1], b"test\0plaintext"),
    ] {
        let ciphertext = aead::seal_with_nonce(&key, aad, plaintext, &nonce).unwrap();
        assert_eq!(
            aead::open(&key, aad, &ciphertext).unwrap().as_bytes(),
            plaintext
        );
        vectors.push(json!({
            "key": b64::encode(key.as_bytes()),
            "nonce": b64::encode(&nonce),
            "aad": b64::encode(aad),
            "plaintext": b64::encode(plaintext),
            "ciphertext": b64::encode(&ciphertext),
        }));
    }
    json!({"suite": labels::SUITE, "vectors": vectors})
}

fn stream_vectors() -> Value {
    let key = Secret32::from_bytes(bytes::<32>(0));
    let mut vectors = Vec::new();
    for (prefix, aad, plaintext) in [
        (bytes::<PREFIX_LEN>(32), b"".as_slice(), b"".as_slice()),
        (bytes::<PREFIX_LEN>(64), &[0, 255, 1], b"test\0file"),
    ] {
        let ciphertext = stream::seal_with_prefix(&key, aad, plaintext, prefix).unwrap();
        assert_eq!(
            stream::stream_open(&key, aad, &ciphertext)
                .unwrap()
                .as_bytes(),
            plaintext
        );
        vectors.push(json!({
            "key": b64::encode(key.as_bytes()),
            "prefix": b64::encode(&prefix),
            "aad": b64::encode(aad),
            "plaintext": b64::encode(plaintext),
            "ciphertext": b64::encode(&ciphertext),
        }));
    }

    let prefix = bytes::<PREFIX_LEN>(96);
    let aad = b"two chunks";
    let len = CHUNK_LEN + 1;
    let byte = 17;
    let ciphertext = stream::seal_with_prefix(&key, aad, &vec![byte; len], prefix).unwrap();
    let second_chunk = HEADER_LEN + CHUNK_CIPHERTEXT_LEN;
    vectors.push(json!({
        "key": b64::encode(key.as_bytes()),
        "prefix": b64::encode(&prefix),
        "aad": b64::encode(aad),
        "plaintext_repeat": {"byte": byte, "count": len},
        "ciphertext_len": ciphertext.len(),
        "ciphertext_sha256": b64::encode(&Sha256::digest(&ciphertext)),
        "header": b64::encode(&ciphertext[..HEADER_LEN]),
        "first_chunk_tag": b64::encode(&ciphertext[second_chunk - TAG_LEN..second_chunk]),
        "final_chunk": b64::encode(&ciphertext[second_chunk..]),
    }));
    json!({"suite": labels::SUITE, "vectors": vectors})
}

fn padme_vectors() -> Value {
    let vectors: Vec<_> = [
        0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 65, 129, 257, 513, 1025, 2049, 4097, 65535, 65536,
        65537,
    ]
    .into_iter()
    .map(|len| json!({"length": len, "padded_length": pad::padme(len).unwrap()}))
    .collect();
    json!({"suite": labels::SUITE, "vectors": vectors})
}

fn share_vectors() -> Value {
    let link = Secret32::from_bytes(bytes::<32>(0));
    let owner = Secret32::from_bytes(bytes::<32>(32));
    let id = bytes::<16>(64);
    let kek = Secret32::from_bytes(bytes::<32>(80));
    let raw_server_key = scalar(7);
    let nonce = bytes::<NONCE_LEN>(112);
    let wrapped = aead::seal_with_nonce(
        &kek,
        &share::share_aad(labels::OPRF_KEY, &id),
        raw_server_key.as_bytes(),
        &nonce,
    )
    .unwrap();
    let server = share::unwrap_oprf_key(&kek, &id, &wrapped).unwrap();

    let mut vectors = Vec::new();
    for password in [None, Some("\u{ff54}\u{ff45}\u{ff53}\u{ff54} e\u{301}")] {
        let material = share::Material::new(&link, password).unwrap();
        let input = material.oprf_input().unwrap();
        let (blinded, client) = oprf::blind_with_scalar(input.as_bytes(), scalar(9)).unwrap();
        let evaluated = server.blind_evaluate(&blinded).unwrap();
        let output = client.finalize(&evaluated).unwrap();
        let root = material.root(output.as_bytes(), &id).unwrap();
        let keys = share::keys_from_root(&root).unwrap();
        vectors.push(json!({
            "password": password,
            "password_flag": u8::from(password.is_some()),
            "oprf_input": b64::encode(input.as_bytes()),
            "blinded": b64::encode(&blinded),
            "evaluated": b64::encode(&evaluated),
            "oprf_output": b64::encode(output.as_bytes()),
            "root": b64::encode(root.as_bytes()),
            "manifest_key": b64::encode(keys.manifest_key.as_bytes()),
            "access_tag": b64::encode(keys.access_tag.as_bytes()),
            "access_verifier": b64::encode(&share::access_verifier(&keys.access_tag)),
        }));
    }
    json!({
        "suite": labels::SUITE,
        "link_secret": b64::encode(link.as_bytes()),
        "share_id": b64::encode(&id),
        "owner_token": b64::encode(owner.as_bytes()),
        "owner_verifier": b64::encode(&share::owner_verifier(&owner)),
        "oprf_key": b64::encode(raw_server_key.as_bytes()),
        "blind": b64::encode(scalar(9).as_bytes()),
        "kek": b64::encode(kek.as_bytes()),
        "wrap_nonce": b64::encode(&nonce),
        "wrapped_oprf_key": b64::encode(&wrapped),
        "password_salt": b64::encode(&*share::password_salt(&link).unwrap()),
        "vectors": vectors,
    })
}

fn rfc_oprf_vector() -> Value {
    // RFC 9497 Appendix A.1.1.1, converted from hexadecimal to base64url.
    json!({
        "source": "https://www.rfc-editor.org/rfc/rfc9497.html#appendix-A.1.1.1",
        "input": "AA",
        "oprf_key": "XrzqXuNwI8y5_C0gGfnXc3voVZGuhlL_qe8PTTcGOw4",
        "blind": "ZNN67SKif1GR3hwdafrbiZ2IYrWOtCIAKeA27EwfZwY",
        "blinded": "YJoK5owVo89pA3ZkYTB-XIuy-V5-ZVDh_6LcmeQSgDw",
        "evaluated": "fsZXiuUSCVjrLbF0V1j_N553y2T-d7Cy2MyRfqCGnH4",
        "output": "UndZw9k2byd9jGAgQY2Wuzk7oq-yD_kN8j-3cIJk4vOrkTXjvWmVWFHeSx-f6KCXM5Zxm3kSup7oqn0LXiS89g",
    })
}
