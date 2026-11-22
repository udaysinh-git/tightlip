#!/usr/bin/env python3
"""Independently check the vector fields supported by the allowed libraries."""

from base64 import urlsafe_b64decode
from hashlib import sha256
import json
from pathlib import Path
from unicodedata import normalize

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS = Path(__file__).resolve().parents[2] / "docs" / "vectors"
NAMESPACE = b"tightlip/v1/"
AEAD = NAMESPACE + b"aead"
STREAM = NAMESPACE + b"stream"
PW_SALT = NAMESPACE + b"pw-salt"
OWNER_VERIFIER = NAMESPACE + b"owner-verifier"
OPRF_KEY = NAMESPACE + b"oprf-key"
OPRF_INPUT = NAMESPACE + b"oprf-input"
ROOT = NAMESPACE + b"root"
MANIFEST_KEY = NAMESPACE + b"manifest-key"
ACCESS = NAMESPACE + b"access"
ACCESS_VERIFIER = NAMESPACE + b"access-verifier"
EVAL_AUTH = NAMESPACE + b"eval-auth"
EVAL_VERIFIER = NAMESPACE + b"eval-verifier"
CHUNK = 65536
TAG = 16


def decode(text):
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


def kdf(salt, ikm, info, length):
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def check(actual, expected, field):
    if actual != expected:
        raise ValueError(f"Vector mismatch: {field}")


def field(vector, name, value):
    check(value, decode(vector[name]), name)


def verify_kdf(document):
    for vector in document["vectors"]:
        info = decode(vector["info"])
        if not info.startswith(vector["label"].encode("ascii")):
            raise ValueError(f"Missing KDF label: {vector['label']}")
        field(vector, "output", kdf(decode(vector["salt"]), decode(vector["ikm"]),
                                    info, len(decode(vector["output"]))))


def verify_padme(document):
    for vector in document["vectors"]:
        length = vector["length"]
        exponent = length.bit_length() - 1
        granularity = 1 << max(0, exponent - exponent.bit_length())
        padded = ((length + granularity - 1) // granularity) * granularity
        check(padded, vector["padded_length"], f"padme({length})")


def commitment(key, nonce, label, aad):
    info = label + len(aad).to_bytes(4, "big") + aad
    return nonce + kdf(nonce, key, info, 64)[32:]


def verify_seal(document):
    for vector in document["vectors"]:
        ciphertext = decode(vector["ciphertext"])
        header = commitment(decode(vector["key"]), decode(vector["nonce"]), AEAD, decode(vector["aad"]))
        check(ciphertext[:len(header)], header, "seal commitment")
        check(len(ciphertext), len(header) + len(decode(vector["plaintext"])) + TAG, "seal length")


def verify_stream(document):
    for vector in document["vectors"]:
        header = commitment(decode(vector["key"]), decode(vector["prefix"]), STREAM, decode(vector["aad"]))
        if "ciphertext" in vector:
            ciphertext = decode(vector["ciphertext"])
            check(ciphertext[:len(header)], header, "stream commitment")
            check(len(ciphertext), len(header) + len(decode(vector["plaintext"])) + TAG, "stream length")
        else:
            field(vector, "header", header)
            length = vector["plaintext_repeat"]["count"]
            chunks = (length + CHUNK - 1) // CHUNK
            check(vector["ciphertext_len"], len(header) + length + chunks * TAG, "stream length")


def verify_share(document):
    link = decode(document["link_secret"])
    share_id = decode(document["share_id"])
    owner = decode(document["owner_token"])
    salt = kdf(b"", link, PW_SALT, 16)
    field(document, "password_salt", salt)
    field(document, "owner_verifier", sha256(OWNER_VERIFIER + owner).digest())
    wrapped = decode(document["wrapped_oprf_key"])
    header = commitment(decode(document["kek"]), decode(document["wrap_nonce"]),
                        AEAD, OPRF_KEY + share_id)
    check(wrapped[:len(header)], header, "wrapped key commitment")
    check(len(wrapped), len(header) + 32 + TAG, "wrapped key length")
    for vector in document["vectors"]:
        password = vector["password"]
        flag = bytes([password is not None])
        check(flag[0], vector["password_flag"], "password_flag")
        password_key = b"" if password is None else hash_secret_raw(
            normalize("NFKC", password).encode(), salt, time_cost=3, memory_cost=65536,
            parallelism=1, hash_len=32, type=Type.ID, version=19,
        )
        ikm = link + password_key
        field(vector, "oprf_input", kdf(b"", ikm, OPRF_INPUT + flag, 32))
        root = kdf(decode(vector["oprf_output"]), ikm, ROOT + flag + share_id, 32)
        field(vector, "root", root)
        field(vector, "manifest_key", kdf(b"", root, MANIFEST_KEY, 32))
        tag = kdf(b"", root, ACCESS, 32)
        field(vector, "access_tag", tag)
        field(vector, "access_verifier", sha256(ACCESS_VERIFIER + tag).digest())


def verify_eval(document):
    tag = kdf(b"", decode(document["link_secret"]), EVAL_AUTH + decode(document["share_id"]), 32)
    field(document, "eval_tag", tag)
    field(document, "eval_verifier", sha256(EVAL_VERIFIER + tag).digest())


def main():
    verifiers = {
        "eval_auth": verify_eval,
        "kdf": verify_kdf,
        "padme": verify_padme,
        "seal": verify_seal,
        "share": verify_share,
        "stream_seal": verify_stream,
    }
    check({file.stem for file in VECTORS.glob("*.json")}, set(verifiers) | {"oprf_rfc9497"}, "fixture set")
    for name, verify in verifiers.items():
        document = json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))
        check(document["suite"], "tightlip-v1", "suite")
        verify(document)
        print(f"{name}: checked")
    print("Coverage pending: XChaCha20-Poly1305 ciphertexts and ristretto255 OPRF outputs.")


if __name__ == "__main__":
    main()
