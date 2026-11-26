# Tightlip

Live at [tightlip.buildwithkuro.tech](https://tightlip.buildwithkuro.tech). How it protects a secret, in plain words: [/security](https://tightlip.buildwithkuro.tech/security).

Tightlip shares credentials, text, images and files through end-to-end encrypted
links with an expiry and a view limit. Link shares work without an account.

The sender's browser encrypts the content and uploads ciphertext. The secret
part of the link follows the `#`. HTTP requests omit it, but browsers can store and sync the full URL. You can send the link and key separately. The recipient opens
the link and presses Reveal. The browser uses the link secret, the optional
password and a blinded evaluation from the server to derive the decryption key.
Loading the page or generating a link preview does not spend a view.

## Threat model

The protocol assumes the server may read, alter, replay, swap or withhold stored
data and see traffic after TLS. When both browsers run the intended client, the
server stores ciphertext and metadata, including padded sizes, the expiry,
password flag, view and attempt counts, a wrapped OPRF key, and hashes of
authorization credentials and successful open request IDs. The protocol
spec lists the stored fields. This includes the share ID, pending deadline,
final-attempt deadline, file indices and blob identifiers, grant and open
deadlines, view counts at open, aggregate storage totals and pending
blob deletions. The content, file names, file types,
password and link secret stay private. The client detects tampering with the
encrypted content. The server can deny access at any time.

The server counts new opens by tag holders, enforces expiry and logically
deletes the wrapped per-share key after expiry, the last view or the last
evaluation. An existing file grant can remain active for up to 10 minutes. A
holder can keep plaintext or retain an earlier evaluation and ciphertext.
Freed disk blocks and snapshots may preserve old data. Protect a randomly
generated key encryption key (KEK) separately from the data volume. Old storage
copies plus that key can expose wrapped OPRF keys. New shares require a
credential derived from the link secret to read share details or spend an
attempt. Shares created before this change keep their original rules until
expiry.

The server delivers the JavaScript, so a compromised server can send code that
steals plaintext, passwords or link secrets. Content security policy and
Trusted Types limit some injection. Browser integrity checks cover the page
script, stylesheet and WebAssembly against the expected hashes received from
the origin. The origin can replace the page and the hashes together. Independent
comparison requires a trusted copy of the release manifest. Endpoint malware
and recipients who keep revealed plaintext are outside the threat model.

An independent review examined commit `806ec31` and the deployment available at
the time. See the [protocol spec](docs/SPEC.md) for details.

## Run locally

Use a checkout that includes `crates/wasm` and `web/`. Install Rustup, native
build tools and Node.js 22. Rustup reads the toolchain and WASM target pins
from `rust-toolchain.toml`. The examples use Bash, which is available
in Git for Windows.

```sh
export CARGO_BUILD_JOBS=2
rustup target add wasm32-unknown-unknown
cargo install --locked --version 0.2.130 wasm-bindgen-cli
(cd web && npm ci --ignore-scripts && npm run build)
```

Generate a KEK once and save it somewhere private, such as a password manager.
The command prints 32 random bytes encoded as unpadded base64url.

```sh
node -p "require('node:crypto').randomBytes(32).toString('base64url')"
```

Load the saved key at the prompt and run the server from the repository root.

```sh
read -r -s -p 'Tightlip KEK: ' TIGHTLIP_KEK
printf '\n'
export TIGHTLIP_KEK
cargo run --locked -p tightlip-server
```

Open `http://localhost:8080`. The server stores metadata and blobs in `./data`
and serves the bundle from `./web/dist` by default.

## Self-host with Docker

Build on a host with Docker BuildKit from a clean checkout. Pass the full
source commit as a build argument. Mount a private KEK file readable by the
container user, outside the data volume.

```sh
docker buildx build --load --build-arg "TIGHTLIP_RELEASE_COMMIT=$(git rev-parse HEAD)" -t tightlip:local .
docker volume create tightlip-data
docker run -d --name tightlip --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  --mount type=volume,source=tightlip-data,target=/data \
  --mount "type=bind,source=$TIGHTLIP_HOST_KEK_FILE,target=/run/tightlip-kek,readonly" \
  --env TIGHTLIP_KEK_FILE=/run/tightlip-kek \
  tightlip:local
```

For public hosting, put an HTTPS reverse proxy in front of port `8080`. On
KuroPanel, build from the Dockerfile, mount a persistent volume at `/data`,
mount the KEK file, supply the source commit as a build argument and route
HTTPS to port `8080`. Set `TIGHTLIP_HOST_KEK_FILE` to the absolute host path
for the Docker example above.
The container runs as UID and GID `65532` and probes `/healthz`.

| Variable | Use |
| --- | --- |
| `TIGHTLIP_KEK_FILE` | Preferred. File containing unpadded base64url of 32 random bytes, optionally followed by a newline. Group and world read permissions are rejected on Unix. |
| `TIGHTLIP_KEK` | Used when the file path is unset. Unpadded base64url of 32 random bytes. |
| `TIGHTLIP_KEK_ID` | Nonzero current key ID, default 1. Assign a new ID when rotating the key. |
| `TIGHTLIP_KEK_PREVIOUS_FILE` | Restricted file containing the previous key, in the same format as the current key file. |
| `TIGHTLIP_KEK_PREVIOUS_ID` | ID of the previous key. Set it with the previous key file. ID 0 identifies old unprefixed wraps. |
| `TIGHTLIP_DATA_DIR` | SQLite database and blobs. Defaults to `/data` in Docker and `./data` locally. |
| `TIGHTLIP_WEB_DIR` | Built bundle. Defaults to `/app/web` in Docker and `./web/dist` locally. |
| `PORT` | HTTP listen port. Defaults to `8080`. Match the container port in the proxy or port mapping. |
| `TIGHTLIP_TRUST_PROXY` | Defaults to off. Set to `1` only when a trusted proxy supplies the client IP as the final `X-Forwarded-For` entry and clients cannot reach the server directly. |
| `TIGHTLIP_PUBLIC_URL` | Optional. The server reads this setting. It currently has no effect. |

The following variables override the share limits.

| Variable | Default |
| --- | --- |
| `TIGHTLIP_TTL_SECONDS` | `300:2592000` (minimum and maximum in seconds) |
| `TIGHTLIP_MAX_VIEWS` | `100` |
| `TIGHTLIP_ATTEMPTS` | `5:3` (extra attempts with and without a password) |
| `TIGHTLIP_MANIFEST_BYTES` | `256000` |
| `TIGHTLIP_FILES_PER_SHARE` | `20` |
| `TIGHTLIP_TOTAL_CIPHERTEXT_BYTES` | `25000000` |
| `TIGHTLIP_STORAGE_BYTES` | `5000000000` |
| `TIGHTLIP_PENDING_LIFETIME_SECONDS` | `900` |
| `TIGHTLIP_CREATES_PER_IP` | `30` per hour |

Keep the volume and the same KEK across container replacements. Store a backup
of the KEK separately from the volume. If you lose the KEK, every live share
becomes unreadable, even if you restore the volume.

To rotate, stop the old server. Start with a new key and ID and supply the
previous key file and its ID. Startup rewraps the active OPRF keys in one
transaction. Remove the previous key settings after a successful startup.
When upgrading an installation with unprefixed wraps, keep the current key
and use the default ID to migrate them. Set previous ID 0 if changing the key
during that upgrade. Retain any keys needed to restore older backups.

The independent vector job installs PyNaCl, cryptography and argon2-cffi,
and builds pinned libsodium for its ristretto255 API. To run
`python tools/vectors/verify.py` locally, install the same Python dependencies
and set `TIGHTLIP_VECTOR_SODIUM` to the shared library from that source revision.
The CI workflow records the revision and build commands.

## Check the bundle

With Docker BuildKit available, run `bash scripts/reproducible-check.sh` from a
commit that includes the web app. It builds `HEAD` twice without the Docker
layer cache and compares the files extracted from both images. Pass a deployed
origin as an optional argument to compare the first build with that endpoint.

The build writes `web/dist/release.json` and the server exposes it at
`/.well-known/tightlip-release.json`. Run
`bash scripts/verify-live.sh <origin> <release.json>` with a trusted manifest
to verify the deployed index and assets. Signing the manifest and publishing
it outside the deployment are separate manual release steps.

## Licence

Tightlip is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). If you run a modified version as a network service, you must offer its source to the people who use it. Some interaction code in `web/src` is adapted from Bencho blocks and is covered by the Bencho Pro licence instead; see [NOTICE.md](NOTICE.md).
