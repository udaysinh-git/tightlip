import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError, downloadFile, NetworkError, commitShare, createShare, getMetadata, openShare, retryNetwork, unavailable,
} from "../src/api";
import { SUITE, base64url, errors, record, shareId } from "../src/wire";
import type { ErrorCode } from "../src/wire";

const id = "A".repeat(22);
const value = "A".repeat(43);

function reply(body: object, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("Tightlip v1 wire contract", () => {
  it("validates canonical unpadded encodings and route length", () => {
    expect(shareId(`/s/${id}`)).toBe(id);
    expect(shareId(`/s/${id}/`)).toBeUndefined();
    expect(base64url(`${id.slice(1)}B`, 16)).toBe(false);
    expect(base64url(`${id}==`, 16)).toBe(false);
    expect(base64url(value, 32)).toBe(true);
    expect(base64url("A", 1)).toBe(false);
  });

  it("sends exactly the create and commit fields and uses Unix seconds", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(reply({ id, evaluated: value, upload_token: value, expires_at: 1234567 }, 201))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);
    expect(await createShare(value, 86400, 1, false)).toEqual({
      id, evaluated: value, upload_token: value, expires_at: 1234567,
    });
    await commitShare(id, value, value, value);
    expect(fetch).toHaveBeenNthCalledWith(1, "/api/v1/shares", expect.objectContaining({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        suite: SUITE, blinded: value, ttl_seconds: 86400, max_views: 1, has_password: false,
      }),
    }));
    expect(fetch).toHaveBeenNthCalledWith(2, `/api/v1/shares/${id}/commit`, expect.objectContaining({
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${value}` },
      body: JSON.stringify({ access_verifier: value, owner_verifier: value }),
    }));
  });

  it.each(Object.entries(errors) as [ErrorCode, number][])(
    "maps %s to a user-facing error",
    async (code, status) => {
      vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(reply({ error: code }, status, { "Retry-After": "22" }))));
      await expect(getMetadata(id)).rejects.toBeInstanceOf(ApiError);
      await expect(getMetadata(id)).rejects.toMatchObject({ code, message: expect.stringMatching(/\./) });
      if (code === "not_found") await expect(getMetadata(id)).rejects.toThrow(unavailable);
      if (code === "rate_limited") await expect(getMetadata(id)).rejects.toThrow("22 seconds");
    },
  );

  it("rejects other suites and noncontiguous file indices", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(reply({ suite: "tightlip-v2", has_password: false, expires_at: 1, views_left: 1 }))
      .mockResolvedValueOnce(reply({ manifest: value, grant: value, files: [{ n: 1, size: 100 }] })));
    await expect(getMetadata(id)).rejects.toThrow("unsupported version");
    await expect(openShare(id, value)).rejects.toThrow("unexpected response");
  });

  it("accepts the atomic view count and the previous response shape", async () => {
    const opened = { manifest: value, grant: value, files: [] };
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(reply({ ...opened, views_left: 0 }))
      .mockResolvedValueOnce(reply(opened))
      .mockResolvedValueOnce(reply({ ...opened, views_left: -1 })));
    expect((await openShare(id, value)).views_left).toBe(0);
    expect((await openShare(id, value)).views_left).toBeUndefined();
    await expect(openShare(id, value)).rejects.toThrow("unexpected response");
  });

  it("reuses a random request id across all three backoffs, including a lost response body", async () => {
    vi.useFakeTimers();
    const broken = new Response(new ReadableStream({ start(controller) { controller.error(new Error()); } }));
    const fetch = vi.fn()
      .mockRejectedValueOnce(new TypeError())
      .mockResolvedValueOnce(broken)
      .mockRejectedValueOnce(new TypeError())
      .mockResolvedValueOnce(reply({ manifest: value, grant: value, files: [], views_left: 0 }));
    vi.stubGlobal("fetch", fetch);
    const opened = openShare(id, value);
    for (const [index, delay] of [500, 1500, 4000].entries()) {
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(fetch).toHaveBeenCalledTimes(index + 1);
      await vi.advanceTimersByTimeAsync(1);
    }
    expect((await opened).views_left).toBe(0);
    const request: unknown = JSON.parse(fetch.mock.calls[0]?.[1].body ?? "");
    expect(request).toEqual({ access_tag: value, request_id: expect.any(String) });
    expect(record(request) && base64url(request.request_id, 16)).toBe(true);
    for (const [, init] of fetch.mock.calls) expect(init.body).toBe(JSON.stringify(request));
  });

  it("requests an authenticated suffix and checks the server's range", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response("tail", {
      status: 206, headers: { "Content-Range": "bytes 65603-65606/65607", "Content-Length": "4" },
    }));
    vi.stubGlobal("fetch", fetch);
    const signal = new AbortController().signal;
    const result = await downloadFile(id, 1, value, 65603, 65607, signal);
    expect(await new Response(result).text()).toBe("tail");
    expect(fetch).toHaveBeenCalledWith(`/api/v1/shares/${id}/files/1`, expect.objectContaining({
      headers: { Authorization: `Bearer ${value}`, Range: "bytes=65603-" },
      signal,
    }));

    fetch.mockResolvedValue(new Response("tail", {
      status: 206, headers: { "Content-Range": "bytes 0-3/65607", "Content-Length": "4" },
    }));
    await expect(downloadFile(id, 1, value, 65603, 65607, signal)).rejects.toThrow("unexpected response");
  });

  it("stops retrying a download when the next attempt would exceed the grant deadline", async () => {
    vi.useFakeTimers();
    const work = vi.fn().mockRejectedValue(new NetworkError());
    const failed = expect(retryNetwork(work, Date.now() + 1000)).rejects.toBeInstanceOf(NetworkError);
    await vi.advanceTimersByTimeAsync(500);
    await failed;
    expect(work).toHaveBeenCalledTimes(2);
  });
});
