#!/usr/bin/env python3
"""Verify the frozen fixtures using independent cryptographic libraries."""

from base64 import urlsafe_b64decode
from ctypes import CDLL, c_char_p, c_int, c_size_t, create_string_buffer
from ctypes.util import find_library
from hashlib import sha256, sha512
import json
from os import environ
from pathlib import Path
from unicodedata import normalize

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

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
RISTRETTO_SHA512 = 2
OPRF_DST = b"HashToGroup-OPRFV1-\x00-ristretto255-SHA512"
OPRF_FINALIZE = b"Finalize"


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


def committing_keys(key, nonce, label, aad):
    info = label + len(aad).to_bytes(4, "big") + aad
    keys = kdf(nonce, key, info, 64)
    return keys[:32], nonce + keys[32:]


def seal(key, nonce, aad, plaintext):
    cipher_key, header = committing_keys(key, nonce, AEAD, aad)
    return header + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, cipher_key)


def verify_seal(document):
    for vector in document["vectors"]:
        field(vector, "ciphertext", seal(decode(vector["key"]), decode(vector["nonce"]),
                                         decode(vector["aad"]), decode(vector["plaintext"])))


def verify_stream(document):
    for vector in document["vectors"]:
        prefix, aad = decode(vector["prefix"]), decode(vector["aad"])
        key, header = committing_keys(decode(vector["key"]), prefix, STREAM, aad)
        if "plaintext" in vector:
            plaintext = decode(vector["plaintext"])
        else:
            repeat = vector["plaintext_repeat"]
            plaintext = bytes([repeat["byte"]]) * repeat["count"]
        chunks = []
        for i, offset in enumerate(range(0, max(1, len(plaintext)), CHUNK)):
            end = offset + CHUNK
            nonce = prefix + i.to_bytes(4, "big") + bytes([end >= len(plaintext)])
            chunks.append(crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext[offset:end], aad, nonce, key,
            ))
        ciphertext = header + b"".join(chunks)
        if "ciphertext" in vector:
            field(vector, "ciphertext", ciphertext)
        else:
            field(vector, "header", header)
            field(vector, "first_chunk_tag", chunks[0][-TAG:])
            field(vector, "final_chunk", chunks[-1])
            check(len(ciphertext), vector["ciphertext_len"], "stream length")
            field(vector, "ciphertext_sha256", sha256(ciphertext).digest())


class Ristretto:
    # PyNaCl does not expose ristretto255. Use libsodium's public C API.
    def __init__(self):
        path = environ.get("TIGHTLIP_VECTOR_SODIUM") or find_library("sodium")
        if path is None:
            raise RuntimeError("Set TIGHTLIP_VECTOR_SODIUM to the libsodium library built by the vector job.")
        lib = CDLL(path)
        lib.sodium_init.argtypes = []
        lib.sodium_init.restype = c_int
        if lib.sodium_init() < 0:
            raise RuntimeError("Could not initialize libsodium.")
        if not hasattr(lib, "crypto_core_ristretto255_from_string"):
            raise RuntimeError("The vector verifier needs the pinned libsodium ristretto255 hash-to-group API.")
        self.hash_to_group = lib.crypto_core_ristretto255_from_string
        self.hash_to_group.argtypes = [c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_int]
        self.multiply = lib.crypto_scalarmult_ristretto255
        self.multiply.argtypes = [c_char_p, c_char_p, c_char_p]
        self.invert = lib.crypto_core_ristretto255_scalar_invert
        self.invert.argtypes = [c_char_p, c_char_p]
        for function in (self.hash_to_group, self.multiply, self.invert):
            function.restype = c_int

    def evaluate(self, message, blind, key):
        check(len(blind), 32, "scalar length")
        check(len(key), 32, "OPRF key length")
        point = call_ristretto(self.hash_to_group, OPRF_DST, len(OPRF_DST),
                               message, len(message), RISTRETTO_SHA512)
        blinded = call_ristretto(self.multiply, blind, point)
        evaluated = call_ristretto(self.multiply, key, blinded)
        inverse = call_ristretto(self.invert, blind)
        unblinded = call_ristretto(self.multiply, inverse, evaluated)
        # RFC 9497 section 3.3.1, Finalize.
        output = sha512(len(message).to_bytes(2, "big") + message
                        + len(unblinded).to_bytes(2, "big") + unblinded + OPRF_FINALIZE).digest()
        return blinded, evaluated, output


def call_ristretto(function, *inputs):
    result = create_string_buffer(32)
    check(function(result, *inputs), 0, function.__name__)
    return result.raw


def verify_rfc_oprf(document, ristretto):
    blinded, evaluated, output = ristretto.evaluate(
        decode(document["input"]), decode(document["blind"]), decode(document["oprf_key"]),
    )
    field(document, "blinded", blinded)
    field(document, "evaluated", evaluated)
    field(document, "output", output)


def verify_share(document, ristretto):
    link = decode(document["link_secret"])
    share_id = decode(document["share_id"])
    owner = decode(document["owner_token"])
    salt = kdf(b"", link, PW_SALT, 16)
    field(document, "password_salt", salt)
    field(document, "owner_verifier", sha256(OWNER_VERIFIER + owner).digest())
    key, blind = decode(document["oprf_key"]), decode(document["blind"])
    field(document, "wrapped_oprf_key", seal(
        decode(document["kek"]), decode(document["wrap_nonce"]), OPRF_KEY + share_id, key,
    ))
    for vector in document["vectors"]:
        password = vector["password"]
        flag = bytes([password is not None])
        check(flag[0], vector["password_flag"], "password_flag")
        password_key = b"" if password is None else hash_secret_raw(
            normalize("NFKC", password).encode(), salt, time_cost=3, memory_cost=65536,
            parallelism=1, hash_len=32, type=Type.ID, version=19,
        )
        ikm = link + password_key
        message = kdf(b"", ikm, OPRF_INPUT + flag, 32)
        field(vector, "oprf_input", message)
        blinded, evaluated, output = ristretto.evaluate(message, blind, key)
        field(vector, "blinded", blinded)
        field(vector, "evaluated", evaluated)
        field(vector, "oprf_output", output)
        root = kdf(output, ikm, ROOT + flag + share_id, 32)
        field(vector, "root", root)
        field(vector, "manifest_key", kdf(b"", root, MANIFEST_KEY, 32))
        tag = kdf(b"", root, ACCESS, 32)
        field(vector, "access_tag", tag)
        field(vector, "access_verifier", sha256(ACCESS_VERIFIER + tag).digest())


def verify_eval(document):
    tag = kdf(b"", decode(document["link_secret"]), EVAL_AUTH, 32)
    field(document, "eval_tag", tag)
    field(document, "eval_verifier", sha256(EVAL_VERIFIER + tag).digest())


def main():
    ristretto = Ristretto()
    verifiers = {
        "eval_auth": verify_eval,
        "kdf": verify_kdf,
        "oprf_rfc9497": lambda document: verify_rfc_oprf(document, ristretto),
        "padme": verify_padme,
        "seal": verify_seal,
        "share": lambda document: verify_share(document, ristretto),
        "stream_seal": verify_stream,
    }
    check({file.stem for file in VECTORS.glob("*.json")}, set(verifiers), "fixture set")
    for name, verify in verifiers.items():
        document = json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))
        if name != "oprf_rfc9497":
            check(document["suite"], "tightlip-v1", "suite")
        verify(document)
        print(f"{name}: checked")


if __name__ == "__main__":
    main()
