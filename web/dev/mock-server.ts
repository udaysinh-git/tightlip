import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { API_ROOT, SUITE, base64url, errors, exactFields, integer, limits } from "../src/wire.ts";
import type { ErrorCode } from "../src/wire.ts";

interface OprfKey {
  blind_evaluate(blinded: string): string;
  free(): void;
}

interface MockWasm {
  default(options: { module_or_path: BufferSource }): Promise<unknown>;
  MockOprfKey: { generate(): OprfKey };
  mock_random_id(): string;
  mock_random_token(): string;
  mock_verify_eval(tag: string, verifier: string): boolean;
  mock_verify_access(tag: string, verifier: string): boolean;
  mock_verify_owner(token: string, verifier: string): boolean;
  mock_compare_tokens(first: string, second: string): boolean;
}

interface Stored {
  id: string;
  expiresAt: number;
  pendingUntil: number;
  key?: OprfKey;
  uploadToken?: string;
  hasPassword: boolean;
  views: number;
  attempts: number;
  evalVerifier: string;
  accessVerifier?: string;
  ownerVerifier?: string;
  manifest?: Buffer;
  files: Buffer[];
  fileBytes: number;
  grants: { token: string; expiresAt: number }[];
  finalAttemptUntil?: number;
  opens: Map<string, { viewsLeft: number; expiresAt: number }>;
}

class HttpError extends Error {
  constructor(readonly code: ErrorCode, readonly retry?: number) {
    super(code);
  }
}

function fail(code: ErrorCode): never {
  throw new HttpError(code);
}

function clock() {
  return Math.floor(Date.now() / 1000);
}

function json(response: ServerResponse, status: number, value: object) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

function noContent(response: ServerResponse) {
  response.writeHead(204).end();
}

async function readBody(request: IncomingMessage, mime: string, limit: number): Promise<Buffer> {
  if (request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== mime) {
    fail("bad_request");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false }) as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) fail("too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function jsonBody(request: IncomingMessage): Promise<unknown> {
  const raw = await readBody(request, "application/json", limits.json);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    fail("bad_request");
  }
}

async function fields(request: IncomingMessage, ...keys: string[]) {
  const parsed = await jsonBody(request);
  if (!exactFields(parsed, ...keys)) fail("bad_request");
  return parsed;
}

function bearer(request: IncomingMessage) {
  const header = request.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : "";
  return base64url(token, 32) ? token : "";
}

export async function createMockServer(moduleUrl: URL) {
  const wasm = await import(/* @vite-ignore */ moduleUrl.href) as MockWasm;
  await wasm.default({ module_or_path: new Uint8Array(await readFile(new URL("tightlip_bg.wasm", moduleUrl))) });
  const shares = new Map<string, Stored>();
  const buckets = new Map<string, { tokens: number; at: number }>();

  function destroy(share: Stored) {
    share.key?.free();
    share.key = undefined;
    shares.delete(share.id);
  }

  function find(id: string, now = clock()) {
    const share = shares.get(id);
    if (!share) return undefined;
    const deadline = share.uploadToken ? Math.min(share.expiresAt, share.pendingUntil) : share.expiresAt;
    share.grants = share.grants.filter((grant) => grant.expiresAt > now);
    if (now >= deadline || ((!share.views || (share.finalAttemptUntil ?? Infinity) <= now)
      && !share.grants.length)) {
      destroy(share);
      return undefined;
    }
    return share;
  }

  const interval = setInterval(() => {
    const now = clock();
    for (const id of shares.keys()) find(id, now);
    for (const [address, bucket] of buckets) {
      if (bucket.at + 3600 <= now) buckets.delete(address);
    }
  }, 60_000);
  interval.unref();

  function close() {
    clearInterval(interval);
    for (const share of shares.values()) destroy(share);
    buckets.clear();
  }

  function live(id: string): Stored {
    const share = find(id);
    if (!share || share.uploadToken || !share.key) fail("not_found");
    return share;
  }

  function pending(request: IncomingMessage, id: string): Stored {
    const share = find(id);
    if (!share) fail("not_found");
    if (!share.uploadToken) fail("conflict");
    if (!wasm.mock_compare_tokens(bearer(request), share.uploadToken)) fail("unauthorized");
    return share;
  }

  function chargeCreate(request: IncomingMessage, now: number) {
    const address = request.socket.remoteAddress ?? "";
    const perSecond = limits.createsPerHour / 3600;
    const bucket = buckets.get(address);
    const tokens = bucket
      ? Math.min(limits.createsPerHour, bucket.tokens + (now - bucket.at) * perSecond)
      : limits.createsPerHour;
    if (tokens < 1) throw new HttpError("rate_limited", Math.ceil((1 - tokens) / perSecond));
    buckets.set(address, { tokens: tokens - 1, at: now });
  }

  function blindEvaluate(key: OprfKey, blinded: string) {
    try {
      return key.blind_evaluate(blinded);
    } catch {
      fail("bad_request");
    }
  }

  async function create(request: IncomingMessage, response: ServerResponse) {
    const { suite, blinded, eval_verifier, ttl_seconds, max_views, has_password } =
      await fields(request, "suite", "blinded", "eval_verifier", "ttl_seconds", "max_views", "has_password");
    if (suite !== SUITE || !base64url(blinded, 32) || !base64url(eval_verifier, 32) || typeof has_password !== "boolean"
      || !integer(ttl_seconds, limits.ttlMin, limits.ttlMax) || !integer(max_views, 1, limits.viewsMax)) {
      fail("bad_request");
    }
    const now = clock();
    chargeCreate(request, now);
    let id: string;
    do id = wasm.mock_random_id(); while (shares.has(id));
    const upload_token = wasm.mock_random_token();
    const key = wasm.MockOprfKey.generate();
    let evaluated: string;
    try {
      evaluated = blindEvaluate(key, blinded);
    } catch (error) {
      key.free();
      throw error;
    }
    const expires_at = now + ttl_seconds;
    shares.set(id, {
      id, key, expiresAt: expires_at, pendingUntil: now + limits.pendingSeconds,
      uploadToken: upload_token, hasPassword: has_password, views: max_views, evalVerifier: eval_verifier,
      attempts: max_views + (has_password ? 5 : 3), files: [], fileBytes: 0, grants: [], opens: new Map(),
    });
    json(response, 201, { id, evaluated, upload_token, expires_at });
  }

  async function put(request: IncomingMessage, response: ServerResponse, id: string, index?: number) {
    const before = pending(request, id);
    if (index !== undefined && index !== before.files.length) fail("conflict");
    if (index !== undefined && index >= limits.files) fail("too_large");
    const bound = index === undefined
      ? Math.min(limits.manifest, limits.ciphertext - before.fileBytes)
      : limits.ciphertext - before.fileBytes - (before.manifest?.length ?? 0);
    const body = await readBody(request, "application/octet-stream", bound);
    const share = pending(request, id);
    if (index === undefined) {
      if (share.fileBytes + body.length > limits.ciphertext) fail("too_large");
      share.manifest = body;
    } else {
      if (index !== share.files.length) fail("conflict");
      if (share.fileBytes + body.length + (share.manifest?.length ?? 0) > limits.ciphertext) fail("too_large");
      share.files.push(body);
      share.fileBytes += body.length;
    }
    noContent(response);
  }

  async function evaluate(request: IncomingMessage, response: ServerResponse, id: string) {
    live(id);
    const body = await jsonBody(request);
    const share = live(id);
    if (!exactFields(body, "blinded", "eval_tag") && !exactFields(body, "blinded")) fail("bad_request");
    const { blinded, eval_tag } = body;
    if (typeof blinded !== "string" || (eval_tag != null && typeof eval_tag !== "string")) fail("bad_request");
    if (!base64url(eval_tag, 32) || !wasm.mock_verify_eval(eval_tag, share.evalVerifier)) fail("unauthorized");
    if (!base64url(blinded, 32) || !share.key) fail("bad_request");
    const evaluated = blindEvaluate(share.key, blinded);
    const attempts_left = --share.attempts;
    if (attempts_left === 0) {
      share.key.free();
      share.key = undefined;
      share.finalAttemptUntil = clock() + 120;
    }
    json(response, 200, { evaluated, attempts_left });
  }

  async function open(request: IncomingMessage, response: ServerResponse, id: string) {
    const { access_tag, request_id } = await fields(request, "access_tag", "request_id");
    const now = clock();
    const share = find(id, now);
    if (!share?.manifest || !share.accessVerifier) fail("not_found");
    const openable = share.views > 0 && (share.finalAttemptUntil ?? Infinity) > now;
    const snapshot = typeof request_id === "string" ? share.opens.get(request_id) : undefined;
    if (snapshot && snapshot.expiresAt <= now) fail("not_found");
    const authorized = base64url(access_tag, 32) && wasm.mock_verify_access(access_tag, share.accessVerifier);
    if (!openable && !(snapshot && authorized)) fail("not_found");
    if (!base64url(access_tag, 32) || !base64url(request_id, 16)) fail("bad_request");
    if (!authorized) fail("unauthorized");
    const manifest = share.manifest.toString("base64url");
    const files = share.files.map((blob, n) => ({ n, size: blob.length }));
    const grant = wasm.mock_random_token();
    const opened = snapshot ?? { viewsLeft: --share.views, expiresAt: Math.min(share.expiresAt, now + limits.grantSeconds) };
    share.opens.set(request_id, opened);
    share.grants.push({ token: grant, expiresAt: opened.expiresAt });
    if (share.views === 0) {
      share.key?.free();
      share.key = undefined;
    }
    json(response, 200, { manifest, files, grant, views_left: opened.viewsLeft });
  }

  async function handle(request: IncomingMessage, response: ServerResponse, tail: string) {
    const method = request.method;
    if (tail === "/shares" && method === "POST") return create(request, response);
    const match = /^\/shares\/([^/]+)(?:\/(manifest|commit|eval|open|files\/([^/]+)))?$/.exec(tail);
    if (!match) fail("not_found");
    const [, id, operation, index] = match;
    if (!base64url(id, 16)) fail("bad_request");

    if (method === "GET" && operation === undefined) {
      const share = live(id);
      if (!wasm.mock_verify_eval(bearer(request), share.evalVerifier)) fail("unauthorized");
      return json(response, 200, {
        suite: SUITE, has_password: share.hasPassword, expires_at: share.expiresAt, views_left: share.views,
      });
    }
    if (method === "PUT" && operation === "manifest") return put(request, response, id);
    if (method === "POST" && operation === "commit") {
      pending(request, id);
      const { access_verifier, owner_verifier } = await fields(request, "access_verifier", "owner_verifier");
      const share = pending(request, id);
      if (!base64url(access_verifier, 32) || !base64url(owner_verifier, 32) || !share.manifest) {
        fail("bad_request");
      }
      share.accessVerifier = access_verifier;
      share.ownerVerifier = owner_verifier;
      share.uploadToken = undefined;
      return noContent(response);
    }
    if (method === "POST" && operation === "eval") return evaluate(request, response, id);
    if (method === "POST" && operation === "open") return open(request, response, id);
    if (method === "DELETE" && operation === undefined) {
      const share = find(id);
      if (!share?.ownerVerifier) fail("not_found");
      if (!wasm.mock_verify_owner(bearer(request), share.ownerVerifier)) {
        fail("unauthorized");
      }
      share.key?.free();
      share.key = undefined;
      share.views = 0;
      share.manifest = share.ownerVerifier = share.accessVerifier = undefined;
      share.opens.clear();
      if (!share.grants.length) destroy(share);
      return noContent(response);
    }
    if (index !== undefined && (method === "PUT" || method === "GET")) {
      const n = Number(index);
      if (!/^\d+$/.test(index) || !integer(n)) fail("bad_request");
      if (method === "PUT") return put(request, response, id, n);
      const now = clock();
      const share = find(id, now);
      if (!share || share.uploadToken) fail("not_found");
      const token = bearer(request);
      const valid = share.grants.some((grant) => grant.expiresAt > now && wasm.mock_compare_tokens(token, grant.token));
      if (!valid) fail(share.key ? "unauthorized" : "not_found");
      const file = share.files[n];
      if (!file) fail("not_found");
      const range = request.headers.range;
      const match = range && /^bytes=(\d+)-(\d*)$/.exec(range);
      const start = match ? Number(match[1]) : 0;
      const end = match?.[2] ? Number(match[2]) + 1 : file.length;
      const boundary = (offset: number) => offset >= 51 && (offset - 51) % 65552 === 0;
      if (range && (!match || start >= end || end > file.length || (start !== 0 && !boundary(start))
        || (end !== file.length && (end === 51 || !boundary(end))))) fail("bad_request");
      response.writeHead(range ? 206 : 200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": end - start,
        "Accept-Ranges": "bytes",
        ...(range ? { "Content-Range": `bytes ${start}-${end - 1}/${file.length}` } : {}),
      });
      response.end(file.subarray(start, end));
      return;
    }
    fail("not_found");
  }

  function middleware(request: IncomingMessage, response: ServerResponse, next: () => void) {
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    if (pathname === "/healthz") {
      response.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
      return;
    }
    if (pathname !== API_ROOT && !pathname.startsWith(`${API_ROOT}/`)) {
      next();
      return;
    }
    response.setHeader("Cache-Control", "no-store");
    void handle(request, response, pathname.slice(API_ROOT.length)).catch((cause: unknown) => {
      if (response.headersSent || response.destroyed) return;
      request.resume();
      const error = cause instanceof HttpError ? cause : new HttpError("bad_request");
      if (error.retry !== undefined) response.setHeader("Retry-After", error.retry);
      json(response, errors[error.code], { error: error.code });
    });
  }

  return { middleware, close };
}
