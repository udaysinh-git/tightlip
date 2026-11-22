# Tightlip

Tightlip shares credentials, text, images and files through end-to-end encrypted
links with an expiry and a view limit. Link shares work without an account.

The sender's browser encrypts the content and uploads ciphertext. The secret
part of the link follows the `#` and stays in the browser. The recipient opens
the link and presses Reveal. The browser uses the link secret, the optional
password and a blinded evaluation from the server to derive the decryption key.
Loading the page or generating a link preview does not spend a view.

## Threat model

The protocol assumes the server may read, alter, replay, swap or withhold stored
data and see traffic after TLS. When both browsers run the intended client, the
server sees ciphertext, padded lengths and metadata such as the expiry, view
count and whether a password is required. The content, file names, file types,
password and link secret stay private. The client detects tampering with the
encrypted content. The server can deny access at any time.

The server is trusted to count views, enforce expiry and destroy per-share keys
on time. After expiry or the last view, a saved link and ciphertext are
insufficient unless the holder also completed a valid key evaluation while the
share was live. An honest server requires a request for each password guess and
destroys the share when the attempt limit is reached. A backup of the data
volume without the key encryption key (KEK) reveals no per-share keys.

The server delivers the JavaScript, so a compromised server can send code that
steals plaintext, passwords or link secrets. A static bundle, strict content
security policy, Trusted Types, subresource integrity, same-origin resources and
reproducible build checks reduce delivery risks. A browser still trusts the
server for the page it receives. Endpoint malware and recipients who keep a copy
of revealed plaintext are outside the threat model.

Tightlip has had no external security audit. See the [protocol spec](docs/SPEC.md)
for details.

## Run locally

Use a checkout that includes `crates/wasm` and `web/`. Install stable Rust with
its native build tools and Node.js 22. The examples use Bash, which is available
in Git for Windows.

```sh
export CARGO_BUILD_JOBS=2
rustup target add wasm32-unknown-unknown
cargo install --locked --version 0.2.130 wasm-bindgen-cli
(cd web && npm ci && npm run build)
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

Build on a host with Docker BuildKit from a checkout that includes the web app.
Export the saved `TIGHTLIP_KEK` as shown above before starting the container.

```sh
docker buildx build --load -t tightlip:local .
docker volume create tightlip-data
docker run -d --name tightlip --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  --mount type=volume,source=tightlip-data,target=/data \
  --env TIGHTLIP_KEK \
  tightlip:local
```

For public hosting, put an HTTPS reverse proxy in front of port `8080`. On
KuroPanel, build from the Dockerfile, mount a persistent volume at `/data`,
set the KEK as a secret environment variable and route HTTPS to port `8080`.
The container runs as UID and GID `65532` and probes `/healthz`.

| Variable | Use |
| --- | --- |
| `TIGHTLIP_KEK` | Required. Unpadded base64url of 32 random bytes. |
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
| `TIGHTLIP_TOTAL_CIPHERTEXT_BYTES` | `100000000` |
| `TIGHTLIP_PENDING_LIFETIME_SECONDS` | `900` |
| `TIGHTLIP_CREATES_PER_IP` | `30` per hour |

Keep the volume and the same KEK across container replacements. Store a backup
of the KEK separately from the volume. If you lose the KEK, every live share
becomes unreadable, even if you restore the volume.

## Check the bundle

With the local build tools installed, run `bash scripts/reproducible-check.sh`
from a commit that includes the web app. The script builds two copies of `HEAD`
and compares SHA-256 hashes by relative path for every file in `web/dist/`.
