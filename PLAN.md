# Tightlip

Tightlip shares credentials, text, images and files through end-to-end encrypted links that expire. A full vault with shared collections comes after the links work.

Deployed at `tightlip.buildwithkuro.tech` on KuroPanel. `tightlip.dev` is the domain to buy later. The name is a config value, so a rename touches one file.

## What it has to beat

In February 2026 an ETH Zurich team published attacks on Bitwarden, LastPass, Dashlane and 1Password under a malicious-server model (Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption", USENIX Security 2026, ePrint 2026/058). Twelve of the attacks hit Bitwarden. The classes they found, plus two older results, are the checklist for this design.

| Weakness in existing tools | Source | What Tightlip does |
| --- | --- | --- |
| The server sends KDF settings, so it can lower them | ePrint 2026/058 | KDF parameters are constants of the suite, compiled into the client. The server never supplies them. |
| Integrity per field only, so the server can cut and paste ciphertexts | ePrint 2026/058 | Every ciphertext is bound through its associated data to the suite, share or vault id, object id and role. |
| Public keys arrive unauthenticated, so the server can substitute its own | ePrint 2026/058 | Identity keys sign every key bundle. Contacts are pinned on first use and can be verified by a short phrase. |
| Legacy formats stay accepted, so the server can downgrade | ePrint 2026/058 | One suite per version, no negotiation, no fallback path in the code. |
| AEADs that do not commit to the key allow partitioning oracle attacks on password protected data | Len, Grubbs, Ristenpart, USENIX Security 2021 | All encryption goes through a committing wrapper that binds key, nonce and associated data (Bellare and Hoang, Eurocrypt 2022; Albertini et al., USENIX Security 2022). |
| A share password is an offline guessing target once someone holds the ciphertext | common design | Keys pass through a per share OPRF (RFC 9497) held by the server. Each online guess spends a share attempt. The intended client keeps the password and link secret in the browser. |
| Deleting a row leaves ciphertext in backups and on disk | common design | Expiry and the last view logically delete the wrapped per-share OPRF key. Old copies can persist in snapshots, backups and freed storage. |
| Ciphertext length reveals the secret length | Nikitin et al., PURBs, PETS 2019 | Padmé padding, with a 512 byte floor for small secrets. |
| Harvest now, decrypt later | NIST FIPS 203 | The 256-bit link secret protects confidentiality from someone without the link. Burn, expiry and password guess limits also depend on the classical ristretto255 OPRF. Vault sharing is planned to use X-Wing, the X25519 plus ML-KEM-768 hybrid. |
| A stolen server database can be brute forced | common design | Accounts use OPAQUE (RFC 9807) plus a 256 bit secret key that stays on the device. The server holds nothing that can be guessed offline. |

The server delivers the code that handles plaintext, passwords and link secrets. CSP and Trusted Types limit some injection, and integrity checks detect changes to resources covered by the hashes the client receives. The server can replace the page and its hashes together. A build generates a file-hash manifest for independent comparison once a trusted copy is available. External publication and signing, WAICT enrolment, a CLI and a browser extension are future work.

An independent review covered commit `806ec31` and the deployment available at the time. Its findings guide hardening work.

## Stack

| Part | Choice | Reason |
| --- | --- | --- |
| Crypto core | Rust crate `tightlip-core`, RustCrypto primitives, `voprf` and `opaque-ke` | One implementation for browser, server, CLI and later mobile. Memory safe, `forbid(unsafe_code)`. |
| Browser crypto | `tightlip-core` compiled to WebAssembly, run in a Web Worker | Same code and test vectors as native. Keeps the page responsive during Argon2id. |
| Web app | Solid 2.0 with Vite, static SPA, TypeScript strict, plain CSS | No server rendering: a static bundle can be hashed, pinned and reproduced. |
| Server | Rust, axum, tokio, one binary that also serves the web bundle | Small memory use and fast cold start on the KuroPanel box. |
| Metadata store | SQLite (WAL, `secure_delete`) behind a storage trait | No database port to expose. Postgres can sit behind the same trait later. |
| Blob store | Files on a mounted volume behind the same trait | S3 compatible storage can replace it without touching the protocol. |
| Hosting | KuroPanel, Dockerfile build, one volume for `/data` | Push to deploy. |

## What the first release does

A visitor with no account pastes text, fills in a login, or drops images and files. They pick an expiry, a view limit and an optional password, and get a link. The secret half of the link sits after the `#` and never reaches the server. The recipient opens the link, presses reveal, and reads or downloads the content. Link previews from chat apps cannot consume a view because nothing is spent until reveal.

The server stores the share ID, expiry and pending deadline, password flag, view and attempt counts, wrapped OPRF key, encrypted manifest and files, evaluation, access and owner verifier hashes, upload token hash, file indices, blob identifiers and ciphertext sizes. It also stores grant hashes and expiry times, hashes of successful open request IDs with their view counts and deadlines, the final-attempt deadline, storage accounting and pending blob deletions. File names and types are inside the encrypted manifest. The Rust process keeps IP buckets in memory. Proxy logging depends on the deployment.

## Milestones

Each milestone ends with its gate passing. The next one does not start before that.

### M1: crypto core

`crates/core` implements `docs/SPEC.md` sections 2 to 6: KDF labels, committing AEAD, STREAM, Padmé, the OPRF wrappers and the link share key schedule, for both client and server roles.

Gate: `cargo test -p tightlip-core` and `cargo clippy --all-targets -- -D warnings` pass. Tests include known answer vectors frozen in `docs/vectors/`, property tests for round trips, tamper tests on every region of a ciphertext, key commitment tests, and STREAM truncation, reorder and duplicate tests.

### M2: server

`crates/server` implements the API in SPEC section 7 with SQLite and disk blobs, the expiry sweeper, rate limits, security headers and `/healthz`.

Gate: integration tests drive a full create, eval, open, download and delete cycle over HTTP using `tightlip-core` as the client. They check the view limit under concurrent opens, the status and body for unavailable shares, and logical key and blob removal through the storage layer.

### M3: web app

`crates/wasm` exposes the client role to the browser. `web/` is the Solid 2.0 SPA with a compose view and a reveal view.

Gate: a Playwright test creates a text share, a login share and an image share and reveals each in a second browser context. The CSP from SPEC section 8 is active with zero violations. The JavaScript is under 60 kB gzipped, not counting the WebAssembly module.

### M4: ship

Dockerfile, KuroPanel app with a `/data` volume, domain and TLS, reproducible build check, README with the threat model.

Gate: the share cycle works on the public URL, two clean builds produce identical bundle hashes, and the container restarts without losing live shares.

### M5: accounts and vault

OPAQUE sign in with a device secret key, the key hierarchy, encrypted items with signed manifests for rollback detection, and a recovery kit. SPEC part 2 is written and reviewed before any code.

### M6: shared vaults

Identity keys, X-Wing key wrapping with sender authentication, contact pinning and verification, member removal with key rotation.

### Later

Passkey sign in through the WebAuthn PRF extension, CLI, browser extension, key transparency log, pricing.

After all shares created before evaluation authorization have expired, remove the null-verifier path for metadata and evaluation. Use the deployment's maximum configured TTL to determine when the last legacy share can expire.

## Open decisions

The licence (AGPL-3.0 like the Bitwarden server, or Apache-2.0) is undecided and no licence file ships until it is.

`tightlip.dev` and `tightlip.app` were unregistered on 2026-11-22. The registrar checkout confirms whether the registry prices them as standard.
