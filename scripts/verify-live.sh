#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    printf 'Usage: %s <origin> <release.json>\n' "$0" >&2
    exit 2
fi

exec python3 - "$@" <<'PY'
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class Index(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = set()

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "script" and "src" in attrs:
            self.assets.add(attrs["src"])
        elif tag == "link" and "href" in attrs:
            self.assets.add(attrs["href"])


origin, manifest = sys.argv[1:]
origin = origin.rstrip("/")
parsed = urlsplit(origin)
if (parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )) or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
    sys.exit("Use an HTTPS origin or a loopback HTTP origin.")
release = json.loads(Path(manifest).read_text(encoding="utf-8"))
commit = release.get("commit", "")
if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
    sys.exit("Invalid release commit.")
files = release.get("files")
if not isinstance(files, dict) or "index.html" not in files:
    sys.exit("Release manifest must include index.html.")
for path, digest in files.items():
    if path != "index.html" and not re.fullmatch(r"assets/[\w.-]+(?:/[\w.-]+)*", path, re.ASCII):
        sys.exit(f"Unexpected release path: {path!r}")
    if any(part in {".", ".."} for part in path.split("/")):
        sys.exit(f"Invalid release path: {path!r}")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        sys.exit(f"Invalid SHA-256 for {path!r}")

http = build_opener(NoRedirect())

def download(path):
    with http.open(Request(origin + path, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"}),
                   timeout=30) as response:
        return response.read()

def verify(path, body):
    if hashlib.sha256(body).hexdigest() != files[path]:
        sys.exit(f"SHA-256 mismatch: {path}")

index = download("/")
verify("index.html", index)
references = Index()
references.feed(index.decode("utf-8"))
for asset in sorted(references.assets):
    if not asset or not asset.startswith("/assets/") or asset[1:] not in files:
        sys.exit(f"Asset absent from manifest: {asset!r}")
for path in sorted(files.keys() - {"index.html"}):
    verify(path, download("/" + path))
print(f"Verified {len(files)} files for {commit} at {origin}.")
PY
