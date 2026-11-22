export const SUITE = "tightlip-v1";
export const API_ROOT = "/api/v1";

export const limits = {
  json: 16_000,
  manifest: 256_000,
  files: 20,
  ciphertext: 100_000_000,
  ttlMin: 300,
  ttlMax: 2_592_000,
  viewsMax: 100,
  pendingSeconds: 900,
  grantSeconds: 600,
  createsPerHour: 30,
} as const;

export const errors = {
  bad_request: 400,
  unauthorized: 401,
  not_found: 404,
  conflict: 409,
  too_large: 413,
  rate_limited: 429,
} as const;

export type ErrorCode = keyof typeof errors;

export function errorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && Object.hasOwn(errors, value);
}

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

export function base64url(value: unknown, bytes?: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  if (bytes !== undefined && value.length !== Math.ceil(bytes * 4 / 3)) return false;
  const remainder = value.length % 4;
  if (remainder === 1) return false;
  // The unused low bits in the last character must be zero.
  if (remainder === 2) return /[AQgw]$/.test(value);
  if (remainder === 3) return /[AEIMQUYcgkosw048]$/.test(value);
  return true;
}

export function shareId(path: string): string | undefined {
  const id = path.startsWith("/s/") ? path.slice(3) : undefined;
  return base64url(id, 16) ? id : undefined;
}

export function exactFields(value: unknown, ...fields: string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === fields.length
    && fields.every((field) => Object.hasOwn(value, field));
}
