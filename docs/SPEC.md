# Tightlip protocol, part 1: link shares

Suite identifier: `tightlip-v1`. A client or server that sees any other identifier refuses to proceed. There is no negotiation.

## 1. Threat model

The server is assumed malicious for confidentiality and integrity of content: it may read, alter, replay, swap or withhold anything it stores, and it sees all traffic after TLS. It must still learn nothing about a share's content, file names, types or password, and any alteration must be detected by the client.

The server is trusted for three things it alone can do: counting views, refusing requests after expiry, and destroying keys on time. A malicious server can ignore limits for itself, but it gains nothing by doing so because it never holds the link secret.

Out of scope for part 1: a recipient who copies the plaintext after a legitimate view, malware on either endpoint, and a server that serves altered JavaScript (see section 8 for the mitigations in place).

Security goals when the server is honest:

1. After expiry or the last view, new evaluations stop and the server logically removes the wrapped key. A holder who evaluated while the share was live and retained the answer can still decrypt ciphertext they saved or can retrieve. Files stay available to existing grants until their deadlines. Physical erasure depends on the underlying storage, including filesystems, WAL blocks and snapshots.
2. A party with the link and without the per-share OPRF key needs one evaluation per password guess. The server caps evaluations per share. An operator with the OPRF key and the link can guess offline at the Argon2id cost.
3. A database or disk backup taken without the server's key encryption key reveals no OPRF keys.

## 2. Conventions

Integers are big-endian. `u32(n)` is four bytes. `lp(x)` is `u32(len(x)) || x`. `||` is concatenation. Labels are ASCII without a terminator. Text encodings of bytes use base64url without padding.

`kdf(salt, ikm, info, len)` is HKDF-SHA-512 (RFC 5869), extract then expand. An empty salt is the empty string.

Random bytes come from the operating system CSPRNG (`getrandom`).

Rust secret types zeroize their own storage on drop. Browser strings and HTTP buffers can retain copies outside these types. A KEK supplied in the process environment also remains there for the process lifetime. Rust compares secrets and tags with `subtle`.

## 3. Committing AEAD

The base cipher is XChaCha20-Poly1305. It does not commit to its key, so every use goes through this wrapper, which commits to key, nonce and associated data.

`seal(K, A, P)` with a 32 byte key `K`, associated data `A` of at most 1024 bytes, and plaintext `P`:

```
N   = random(24)
okm = kdf(salt = N, ikm = K, info = "tightlip/v1/aead" || lp(A), len = 64)
Ke  = okm[0..32]
Kc  = okm[32..64]
C   = XChaCha20-Poly1305.encrypt(key = Ke, nonce = N, plaintext = P, aad = A)
out = N || Kc || C
```

`open(K, A, out)` splits `out`, recomputes `okm`, compares `Kc` in constant time and fails before any decryption if it differs, then decrypts. Output shorter than 24 + 32 + 16 bytes fails. All failures return the same error.

## 4. STREAM for files

Files are encrypted in chunks so they can be processed without holding the whole file in memory. The construction is STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015).

`stream_seal(Kf, A, plaintext)` with a 32 byte file key `Kf` used for exactly one file:

```
prefix = random(19)
okm    = kdf(salt = prefix, ikm = Kf, info = "tightlip/v1/stream" || lp(A), len = 64)
Ks     = okm[0..32]
Kc     = okm[32..64]
header = prefix || Kc                         (51 bytes)
```

The plaintext is split into chunks of 65536 bytes. The last chunk holds the remaining 0 to 65536 bytes and always exists, so an empty plaintext is one empty chunk, and a plaintext whose length is a multiple of 65536 ends with a full chunk marked final. Chunk `i`, counted from 0:

```
nonce_i = prefix || u32(i) || (0x01 if final else 0x00)
ct_i    = XChaCha20-Poly1305.encrypt(key = Ks, nonce = nonce_i, plaintext = chunk_i, aad = A)
```

The output is `header || ct_0 || ct_1 || ...`. Every chunk ciphertext is 16 bytes longer than its plaintext. A stream has at most 2^32 - 1 chunks.

Decryption checks `Kc` first. It fails if any chunk fails, if the input ends before a chunk marked final, or if bytes follow the final chunk. The API is incremental (init, update, finish) on both sides, and decrypted bytes of a chunk are released only after that chunk authenticates.

## 5. Padding

`padme(L)` (Nikitin et al., PETS 2019), for `L >= 2`:

```
E    = floor(log2(L))
S    = floor(log2(E)) + 1
mask = (1 << (E - S)) - 1
padme(L) = (L + mask) & ~mask
```

For `L < 2`, `padme(L) = L`.

To pad a byte string of length `L` to a target `T > L`: append `0x80`, then zero bytes up to `T`. To unpad: strip trailing zeros, require and remove the final `0x80`.

The manifest is padded to `T = max(512, padme(L + 1))`. A file is padded to `T = padme(L + 1)` before `stream_seal`.

## 6. Link share key schedule

### 6.1 Secrets

```
link_secret = random(32)        in the URL fragment, never sent to the server
share_id    = random(16)        chosen by the server, public to link holders
owner_token = random(32)        kept by the creator, used to delete the share
k           = OPRF private key  generated by the server per share
```

The link is `https://<host>/s/<b64url(share_id)>#<b64url(link_secret)>`.

### 6.2 Password

Without a password, `pw_key` is the empty string and `pw_flag = 0x00`.

With a password, `pw_flag = 0x01` and:

```
salt   = kdf(salt = "", ikm = link_secret, info = "tightlip/v1/pw-salt", len = 16)
pw_key = Argon2id(password = UTF-8(NFKC(password)), salt = salt,
                  m = 65536 KiB, t = 3, p = 1, len = 32)
```

The Argon2id parameters are constants of the suite. They are never read from the server or from the link.

### 6.3 OPRF

The OPRF is RFC 9497 `OPRF(ristretto255, SHA-512)` in base mode (mode 0x00).

```
oprf_input = kdf(salt = "", ikm = link_secret || pw_key,
                 info = "tightlip/v1/oprf-input" || pw_flag, len = 32)
blinded    = Blind(oprf_input)                32 bytes, sent to the server
evaluated  = BlindEvaluate(k, blinded)        32 bytes, returned by the server
oprf_out   = Finalize(oprf_input, blind, evaluated)   64 bytes
```

The server rejects a blinded element that does not decode to a valid non-identity point.

### 6.4 Keys

```
root         = kdf(salt = oprf_out, ikm = link_secret || pw_key,
                   info = "tightlip/v1/root" || pw_flag || share_id, len = 32)
manifest_key = kdf("", root, "tightlip/v1/manifest-key", 32)
access_tag   = kdf("", root, "tightlip/v1/access", 32)

access_verifier = SHA-256("tightlip/v1/access-verifier" || access_tag)
owner_verifier  = SHA-256("tightlip/v1/owner-verifier" || owner_token)
```

The server stores the access and owner verifiers. It learns `access_tag` only when a client presents it to open the share.

The client derives the evaluation credential from the random link secret before creating the share.

```
eval_tag      = kdf("", link_secret, "tightlip/v1/eval-auth", 32)
eval_verifier = SHA-256("tightlip/v1/eval-verifier" || eval_tag)
```

The server stores `eval_verifier` at creation. The client presents `eval_tag` for metadata and evaluation. It is a reusable bearer credential independent of the password. Its holder can use all remaining attempts.

### 6.5 Manifest

The manifest is UTF-8 JSON:

```json
{
  "v": 1,
  "note": "optional free text",
  "login": { "title": "", "username": "", "password": "", "url": "", "totp": "", "note": "" },
  "files": [ { "name": "scan.png", "mime": "image/png", "size": 48213, "key": "<b64url 32 bytes>" } ]
}
```

`note`, `login` and `files` are each optional. A valid manifest contains a nonempty note, a login with at least one field, or a nonempty file list. Every field of `login` is optional. `size` is the true length before padding. `key` is a fresh random file key. A file entry can include `orientation`, a JPEG EXIF orientation integer from 1 to 8. The client omits it when absent and rejects values outside that range.

```
manifest_ct = seal(manifest_key, "tightlip/v1/manifest" || share_id, pad(manifest_json))
file_ct[i]  = stream_seal(files[i].key, "tightlip/v1/file" || share_id || u32(i), pad(file_bytes))
```

A client that opens a share rejects a manifest whose `v` is not 1, whose file count differs from the number of blobs the server lists, or whose decrypted file is shorter than its `size`. It truncates each decrypted file to `size`.

### 6.6 Server key storage

The server holds a randomly generated 32 byte key encryption key `KEK` and a nonzero key ID. Supply the key in a restricted file outside the data volume or through the environment. `TIGHTLIP_KEK_ID` is an unsigned 32-bit integer and defaults to 1. The server stores each OPRF key as:

```
k_wrapped = u32(kek_id) || seal(KEK, "tightlip/v1/oprf-key" || share_id || u32(kek_id), k)
```

The prefixed format is 108 bytes. Existing unprefixed 104 byte wraps have implicit ID 0 and use `"tightlip/v1/oprf-key" || share_id` as associated data. A prefixed ID of 0 is invalid.

On startup, the server rewraps retained keys for unexpired live and pending shares under the current key in one SQLite transaction. For rotation, set `TIGHTLIP_KEK_PREVIOUS_FILE` and `TIGHTLIP_KEK_PREVIOUS_ID` together. The previous ID must differ from the current ID. A previous ID of 0 selects the unprefixed format. With no previous key configured, ID 0 uses the current key to migrate an existing database while keeping its KEK. A retained wrap with an unknown ID or a wrap that fails to authenticate aborts startup and rolls back the rewraps. After a successful rotation, the previous key can be removed from the server configuration.

## 7. HTTP API

All paths are under `/api/v1`. JSON bodies are small and capped at 16 kB. Binary bodies are `application/octet-stream`. Every API response carries `Cache-Control: no-store`.

A share starts pending (created, content not yet committed) and becomes live on commit. Subject to the final attempt, replay and grant rules below, missing, expired, burned and pending shares answer recipient requests with the same `404` and response body. The server runs dummy cryptographic work on unavailable recipient paths where needed to reduce timing differences. Response times can still vary.

| Request | Body | Effect |
| --- | --- | --- |
| `POST /shares` | `{suite, blinded, eval_verifier, ttl_seconds, max_views, has_password}` | Creates a pending share and its OPRF key. The server chooses the share ID and returns `201 {id, evaluated, upload_token, expires_at}`. This evaluation is not counted. |
| `PUT /shares/{id}/manifest` | `manifest_ct` | Needs `Authorization: Bearer <upload_token>`. Pending shares only. |
| `PUT /shares/{id}/files/{n}` | `file_ct[n]`, streamed | Same auth. `n` counts from 0 with no gaps. |
| `POST /shares/{id}/commit` | `{access_verifier, owner_verifier}` | Same auth. Makes the share live and invalidates the upload token. |
| `GET /shares/{id}` | none | Needs `Authorization: Bearer <eval_tag>`. Returns `{suite, has_password, expires_at, views_left}`. Changes nothing. |
| `POST /shares/{id}/eval` | `{blinded, eval_tag}` | With a correct tag, spends one attempt. Returns `{evaluated, attempts_left}`, including the evaluation that brings attempts to zero. At zero the server immediately deletes the wrapped OPRF key. Metadata and further evaluations return `404`. An open with a correct access tag can still spend a remaining view for 120 seconds, bounded by the original share expiry. |
| `POST /shares/{id}/open` | `{access_tag, request_id}` | If the tag matches the verifier and a view remains, spends one view atomically and returns `{manifest, files: [{n, size}], grant, views_left}`, where `views_left` is the count after this view. Within the grant window, the same request ID and correct tag return the same manifest, file list and view count with a fresh grant token for the rest of that window. A wrong tag on a share available for a new open returns `401` and spends nothing. Once a share is spent, only an authenticated replay can open it. Other open requests return `404`. |
| `GET /shares/{id}/files/{n}` | none | Needs `Authorization: Bearer <grant>`. The grant window lasts 10 minutes from the first open, bounded by the original share expiry. |
| `DELETE /shares/{id}` | none | Needs `Authorization: Bearer <b64url(owner_token)>`. Destroys the share. |

Limits, all configurable by environment with these defaults:

| Limit | Default |
| --- | --- |
| `ttl_seconds` | 300 to 2592000 (5 minutes to 30 days) |
| `max_views` | 1 to 100 |
| Attempts | `max_views + 5` with a password, `max_views + 3` without |
| Manifest ciphertext | 256 kB |
| Files per share | 20 |
| Total ciphertext per share (`TIGHTLIP_TOTAL_CIPHERTEXT_BYTES`) | 25 MB |
| Global blob and manifest ciphertext (`TIGHTLIP_STORAGE_BYTES`) | 5 GB |
| Pending share lifetime | 15 minutes |
| Creates per client bucket | 30 per hour, held in memory. IPv4 uses the address and IPv6 uses the /64. Behind a proxy, the socket peer defines the bucket unless trusted forwarding is enabled. |

The access tag is a reusable bearer credential. Views count successful new opens by tag holders. One holder can spend all the remaining views.

On a live share with an evaluation verifier, a missing or wrong evaluation tag returns `401` and spends nothing. The server performs the same dummy evaluation on an authorization failure and an unavailable share. The metadata path hashes and compares a credential on both paths. Existing shares without an evaluation verifier keep their original metadata and evaluation rules until expiry.

The server stores the SHA-256 hash of each successful request ID per share with the grant window and open's view count. Reuse of that ID after its grant window returns `404`. When the last view is spent, the server deletes the wrapped OPRF key immediately and retains the manifest for retries until the last grant expires. After the final attempt window closes, only authenticated replays and granted downloads remain available.

Destroying a share means, in this order: delete the wrapped OPRF key, delete the row, unlink the blobs. A sweeper destroys expired and stale pending shares at least once a minute, and every request checks expiry itself so the sweeper's timing does not matter for correctness.

The Rust process logs method, route template, status and latency. It keeps IP rate buckets in memory and excludes actual share IDs, IP addresses, request bodies, tokens and tags from these logs. Reverse-proxy and provider logging depend on the deployment.

Stored metadata includes the share ID, expiry and pending deadline, password flag, view and attempt counts, wrapped OPRF key, encrypted manifest, evaluation, access and owner verifiers, upload token hash, file indices, blob identifiers and ciphertext sizes, grant hashes and deadlines, hashed open request IDs with deadlines and view counts, the final-attempt deadline, storage totals and pending blob deletions.

The server checks the global ciphertext cap in the transactions that admit creates and uploads. A create at or above the cap, or an upload that would exceed it, returns `429 rate_limited` with `Retry-After: 600`.

### 7.1 Wire conventions

Both the server and the web client build to these rules. Where this subsection and an implementation disagree, the implementation is wrong.

| Item | Encoding |
| --- | --- |
| `{id}` in paths and `id` in JSON | base64url of the 16 byte share id (22 characters) |
| `blinded`, `evaluated`, `eval_tag`, `eval_verifier`, `access_tag`, `access_verifier`, `owner_verifier` | base64url of 32 bytes |
| `upload_token`, `grant` | base64url of 32 random bytes |
| `request_id` | base64url of 16 random bytes. A client generates it once per reveal and reuses it when retrying the open. |
| `manifest` in the `open` response | base64url of `manifest_ct` |
| `expires_at` | integer, Unix seconds |
| `suite` | the string `tightlip-v1` |
| `files[].size` in the `open` response | ciphertext length in bytes, as stored |
| `views_left`, `attempts_left`, `ttl_seconds`, `max_views`, `n` | non-negative integers |

JSON requests send `Content-Type: application/json`. Unknown JSON fields are rejected. Binary uploads send `Content-Type: application/octet-stream`. Successful `PUT` and `DELETE` requests return `204` with no body. `commit` returns `204`.

Errors return JSON `{"error": "<code>"}` with exactly these pairs:

| Status | Code | When |
| --- | --- | --- |
| 400 | `bad_request` | malformed JSON, unknown fields, wrong `Content-Type`, bad encoding, wrong suite or a value out of range |
| 401 | `unauthorized` | missing or wrong evaluation tag on a live share with a verifier, or wrong access tag, upload token, grant or owner token |
| 404 | `not_found` | every missing, expired, burned or pending share on a recipient route, and unknown routes |
| 409 | `conflict` | file index out of order on a pending share. Uploads and commits on a share that is already committed return `404`, since its upload token no longer exists. |
| 413 | `too_large` | a size or count limit |
| 429 | `rate_limited` | the create limit or the global ciphertext cap, with a `Retry-After` header in seconds |

### 7.2 Static routes

The same process serves the web bundle from `TIGHTLIP_WEB_DIR` (default `./web/dist`).

| Path | Response |
| --- | --- |
| `/`, `/security` and `/s/{id}` | `index.html`, `Cache-Control: no-cache` |
| `/robots.txt` and `/sitemap.xml` | the matching file at the web root, `Cache-Control: public, max-age=3600` |
| `/og.png` | the matching file at the web root, `Cache-Control: public, max-age=86400` |
| `/assets/*` | the file, `Cache-Control: public, max-age=31536000, immutable` |
| `/.well-known/tightlip-release.json` | `release.json`, `Cache-Control: no-cache` |
| `/.well-known/security.txt` | Security disclosure contact and expiry, `Cache-Control: no-cache` |
| `/healthz` | `200`, body `ok` |
| anything else outside `/api/v1` | `404` |

The web client reads the share id from the path and the link secret from the fragment.

## 8. Web delivery

The web app is a static bundle with content hashed file names. The server sends these headers on every response from the application router:

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types tightlip-templates tightlip-worker
Integrity-Policy: blocked-destinations=(script)
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

The page loads its resources from the same origin. The entry script and stylesheet carry subresource integrity hashes. The worker fetches the WebAssembly module with a build-time SHA-384 integrity value and streams it into WebAssembly. The worker script itself uses a same-origin content-hashed URL. A build emits `release.json` containing the source commit and SHA-256 of every other file in `web/dist`. Compare uncached Docker builds to check repeatability and use a trusted copy of the manifest to compare live files. The page origin can replace the HTML, its integrity values and the served manifest together.

The reveal view performs no request that changes state until the person presses reveal. It uses `history.replaceState` to remove the fragment from the address bar. Browsers can still store and sync the full original URL. Recipients can paste a separate key into the keyless page. The client renders decrypted text in text nodes, previews signature-identified JPEG, PNG, GIF and WebP through raster image `blob:` URLs, and creates separate octet-stream downloads.

Before encryption the client strips common metadata from JPEG, PNG and WebP without re-encoding them. JPEG drops `APP1` through `APP15` and `COM`, except the ICC profile in `APP2`. It also drops `APP0` JFXX segments and bytes after `EOI`. PNG keeps only `IHDR PLTE IDAT IEND tRNS gAMA cHRM sRGB iCCP sBIT pHYs cICP acTL fcTL fdAT`. WebP drops `EXIF` and `XMP ` and clears those bits in `VP8X`. The client stores the extracted JPEG orientation in the encrypted manifest. JPEG, PNG and WebP can retain data in the formats or chunks that are preserved.

## 9. Test vectors

`docs/vectors/` holds JSON known answer tests for `kdf` labels, `seal`, `stream_seal`, `padme`, evaluation authorization and the full key schedule with a fixed link secret, password, share id, OPRF key and blind. The Rust tests load these fixtures. The independent CI verifier checks HKDF, Padmé, Argon2id, XChaCha20-Poly1305 ciphertexts, complete STREAM output and RFC 9497 ristretto255 OPRF steps. The original six files stay frozen. Additional scenarios use new files.
