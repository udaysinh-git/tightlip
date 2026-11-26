import { API_ROOT, SUITE, base64url, errorCode, errors, integer, record } from "./wire";
import type { ErrorCode } from "./wire";

export const unavailable = "This share is unavailable. Ask the sender for a new link.";
const interrupted = "The connection was interrupted. Check your network and try again.";
const malformed = "The server sent an unexpected response. Try again later.";
const maxDateSeconds = 8_640_000_000_000;
const retryDelays = [500, 1500, 4000];

export class NetworkError extends Error {
  constructor() {
    super(interrupted);
  }
}

export async function retryNetwork<T>(work: () => Promise<T>, deadline = Infinity): Promise<T> {
  for (const delay of retryDelays) {
    try {
      return await work();
    } catch (error) {
      if (!(error instanceof NetworkError) || Date.now() + delay >= deadline) throw error;
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
      if (Date.now() >= deadline) throw error;
    }
  }
  return work();
}

const messages: Record<ErrorCode, string> = {
  bad_request: "The server rejected the request. Check the link or share options, then try again.",
  unauthorized: "The server rejected your access. Check the password or ask for a new link.",
  not_found: unavailable,
  conflict: "The share changed while it was being saved. Create a new share.",
  too_large: "The share exceeds a size or file count limit. Remove some content and try again.",
  rate_limited: "The server has reached a limit. Wait before trying again.",
};

export class ApiError extends Error {
  constructor(readonly code: ErrorCode, retryAfter?: string | null) {
    const seconds = retryAfter === null || retryAfter === undefined ? undefined : Number(retryAfter);
    super(code === "rate_limited" && integer(seconds)
      ? `The server has reached a limit. Try again in ${seconds} seconds.`
      : messages[code]);
  }
}

function failure(status: number, value: unknown, retryAfter: string | null): Error {
  if (record(value) && errorCode(value.error) && errors[value.error] === status) {
    return new ApiError(value.error, retryAfter);
  }
  return new Error(malformed);
}

async function request(path: string, init: RequestInit, expected: number): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      ...init, cache: "no-store", redirect: "error", credentials: "omit",
    });
  } catch {
    throw new NetworkError();
  }
  if (response.status !== expected) {
    const value: unknown = await response.json().catch(() => undefined);
    throw failure(response.status, value, response.headers.get("Retry-After"));
  }
  return response;
}

async function json(response: Response): Promise<Record<string, unknown>> {
  const body = await response.text().catch(() => { throw new NetworkError(); });
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    throw new Error(malformed);
  }
  if (!record(value)) throw new Error(malformed);
  return value;
}

function bearer(token: string) {
  return { Authorization: `Bearer ${token}` };
}

function post(body: object, token?: string): RequestInit {
  return {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", ...(token && bearer(token)) },
  };
}

function path(id: string): string {
  if (!base64url(id, 16)) throw new ApiError("not_found");
  return `/shares/${id}`;
}

function upload(url: string, body: Blob, token: string, onProgress: (loaded: number) => void) {
  return new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `${API_ROOT}${url}`);
    xhr.responseType = "json";
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("Authorization", bearer(token).Authorization);
    xhr.upload.onprogress = (event) => onProgress(event.loaded);
    xhr.onload = () => {
      if (xhr.status === 204) {
        onProgress(body.size);
        resolve();
      } else {
        reject(failure(xhr.status, xhr.response, xhr.getResponseHeader("Retry-After")));
      }
    };
    xhr.onerror = xhr.onabort = xhr.ontimeout = () => reject(new Error(interrupted));
    xhr.send(body);
  });
}

export async function createShare(
  blinded: string, eval_verifier: string, ttl_seconds: number, max_views: number, has_password: boolean,
) {
  const result = await json(await request("/shares", post({
    suite: SUITE, blinded, eval_verifier, ttl_seconds, max_views, has_password,
  }), 201));
  const { id, evaluated, upload_token, expires_at } = result;
  if (!base64url(id, 16) || !base64url(evaluated, 32)
    || !base64url(upload_token, 32) || !integer(expires_at, 0, maxDateSeconds)) throw new Error(malformed);
  return { id, evaluated, upload_token, expires_at };
}

export function uploadManifest(
  id: string, data: Blob, token: string, onProgress: (loaded: number) => void,
) {
  return upload(`${path(id)}/manifest`, data, token, onProgress);
}

export function uploadFile(
  id: string, n: number, data: Blob, token: string, onProgress: (loaded: number) => void,
) {
  return upload(`${path(id)}/files/${n}`, data, token, onProgress);
}

export async function commitShare(
  id: string, token: string, access_verifier: string, owner_verifier: string,
) {
  await request(`${path(id)}/commit`, post({ access_verifier, owner_verifier }, token), 204);
}

export async function getMetadata(id: string, tag: string) {
  const result = await json(await request(path(id), { headers: bearer(tag) }, 200));
  const { suite, has_password, expires_at, views_left } = result;
  if (suite !== SUITE) throw new Error("This link uses an unsupported version. Ask the sender for a new link.");
  if (typeof has_password !== "boolean" || !integer(expires_at, 0, maxDateSeconds) || !integer(views_left, 1)) {
    throw new Error(malformed);
  }
  return { has_password, expires_at, views_left };
}

export type Metadata = Awaited<ReturnType<typeof getMetadata>>;

export async function evaluate(id: string, blinded: string, eval_tag: string) {
  const result = await json(await request(`${path(id)}/eval`, post({ blinded, eval_tag }), 200));
  const { evaluated, attempts_left } = result;
  if (!base64url(evaluated, 32) || !integer(attempts_left)) throw new Error(malformed);
  return { evaluated, attempts_left };
}

export function openShare(id: string, access_tag: string, accepted?: () => void) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const request_id = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  return retryNetwork(async () => {
    const response = await request(`${path(id)}/open`, post({ access_tag, request_id }), 200);
    accepted?.();
    return readOpenResponse(await json(response));
  });
}

function readOpenResponse(result: Record<string, unknown>) {
  const { manifest, files, grant, views_left } = result;
  if (!base64url(manifest) || !Array.isArray(files) || !base64url(grant, 32)) {
    throw new Error(malformed);
  }
  if (views_left !== undefined && !integer(views_left)) throw new Error(malformed);
  const listed = files.map((file: unknown, n) => {
    if (!record(file) || file.n !== n || !integer(file.size)) throw new Error(malformed);
    return { n, size: file.size };
  });
  return { manifest, files: listed, grant, views_left };
}

export async function downloadFile(
  id: string, n: number, grant: string, start: number, size: number, signal: AbortSignal,
) {
  const headers = start ? { ...bearer(grant), Range: `bytes=${start}-` } : bearer(grant);
  const response = await request(`${path(id)}/files/${n}`, { headers, signal }, start ? 206 : 200);
  if (!response.body || response.headers.get("Content-Length") !== String(size - start)
    || (start && response.headers.get("Content-Range") !== `bytes ${start}-${size - 1}/${size}`)) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(malformed);
  }
  return response.body;
}

export async function deleteShare(id: string, token: string) {
  await request(path(id), { method: "DELETE", headers: bearer(token) }, 204);
}
