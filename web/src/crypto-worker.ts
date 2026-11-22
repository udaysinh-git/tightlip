import init, {
  LinkSecret, OwnerToken, file_header_length, generate_password, strip_image_metadata,
} from "tightlip-wasm/client";
import type { Draft, OpenedManifest, ShareSession } from "tightlip-wasm/client";
import {
  ApiError, commitShare, createShare, deleteShare, downloadFile, evaluate, getMetadata,
  openShare, unavailable, uploadFile, uploadManifest,
} from "./api";
import { scrubType, supportedImage } from "./image-types";
import { limits, shareId } from "./wire";
import type {
  Content, CreateInput, Created, Progress, Reply, Request, Result, Revealed, VisibleFile,
} from "./worker-protocol";

const scope = self as unknown as DedicatedWorkerGlobalScope;
const sliceSize = 64 * 1024;
let ready: ReturnType<typeof init> | undefined;
let owned: { id: string; token: OwnerToken } | undefined;
let recipient: { id: string; secret: LinkSecret; hasPassword: boolean } | undefined;

class UsedViewError extends Error {}

async function sealFile(session: ShareSession, draft: Draft, file: File): Promise<Blob> {
  let source: Blob = file;
  let orientation: number | undefined;
  const mime = scrubType(file.type, new Uint8Array(await file.slice(0, 8).arrayBuffer()));
  if (mime) {
    const original = new Uint8Array(await file.arrayBuffer());
    try {
      const scrubbed = strip_image_metadata(original, mime);
      try {
        const bytes = scrubbed.bytes();
        source = new Blob([bytes]);
        bytes.fill(0);
        orientation = scrubbed.orientation();
      } finally {
        scrubbed.free();
      }
    } finally {
      original.fill(0);
    }
  }

  const encryptor = session.seal_file_init(draft, file.name, mime ?? file.type, source.size, orientation);
  const parts: BlobPart[] = [];
  try {
    parts.push(encryptor.header());
    for (let offset = 0; offset < source.size; offset += sliceSize) {
      const bytes = new Uint8Array(await source.slice(offset, offset + sliceSize).arrayBuffer());
      try {
        const sealed = encryptor.update(bytes);
        if (sealed.byteLength) parts.push(new Blob([sealed]));
      } finally {
        bytes.fill(0);
      }
    }
  } catch (error) {
    encryptor.free();
    throw error;
  }
  // The wasm finish method consumes its handle.
  parts.push(encryptor.finish());
  return new Blob(parts, { type: "application/octet-stream" });
}

async function create(input: CreateInput, progress: (value: Progress) => void): Promise<Created> {
  if (input.files.length > limits.files
    || input.files.reduce((size, file) => size + file.size, 0) > limits.ciphertext) {
    throw new ApiError("too_large");
  }

  const linkSecret = LinkSecret.generate();
  try {
    const token = OwnerToken.generate();
    let keepToken = false;
    try {
      const exchange = linkSecret.start(input.password);
      let created: Awaited<ReturnType<typeof createShare>>;
      try {
        created = await createShare(exchange.blinded(), input.ttl, input.views, input.password !== undefined);
      } catch (error) {
        exchange.free();
        throw error;
      }
      const { id, evaluated, upload_token, expires_at } = created;
      const session = exchange.finish(evaluated, id);
      try {
        const draft = session.draft(JSON.stringify(input.content));
        try {
          const total = input.files.length + 1;
          let ciphertextBytes = 0;
          function report(phase: Progress["phase"], current: number, loaded = 0, size = 0) {
            progress({ phase, current, total, loaded, size });
          }
          for (const [n, file] of input.files.entries()) {
            report("encrypting", n + 1);
            const ciphertext = await sealFile(session, draft, file);
            ciphertextBytes += ciphertext.size;
            if (ciphertextBytes > limits.ciphertext) throw new ApiError("too_large");
            report("uploading", n + 1, 0, ciphertext.size);
            await uploadFile(id, n, ciphertext, upload_token,
              (loaded) => report("uploading", n + 1, loaded, ciphertext.size));
          }
          const ciphertext = new Blob([session.seal_manifest(draft)]);
          if (ciphertext.size > limits.manifest || ciphertextBytes + ciphertext.size > limits.ciphertext) {
            throw new ApiError("too_large");
          }
          report("uploading", total, 0, ciphertext.size);
          await uploadManifest(id, ciphertext, upload_token,
            (loaded) => report("uploading", total, loaded, ciphertext.size));
          await commitShare(id, upload_token, session.access_verifier(), token.verifier());
          owned?.token.free();
          owned = { id, token };
          keepToken = true;
          const link = linkSecret.format(scope.location.host, id);
          // The Vite mock runs on a loopback HTTP origin.
          const local = ["localhost", "127.0.0.1", "[::1]"].includes(scope.location.hostname);
          return { link: import.meta.env.DEV && local && scope.location.protocol === "http:"
            ? `http:${link.slice(6)}` : link,
            expiresAt: expires_at };
        } finally {
          draft.free();
        }
      } finally {
        session.free();
      }
    } finally {
      if (!keepToken) token.free();
    }
  } finally {
    linkSecret.free();
  }
}

async function fetchFile(
  id: string, grant: string, entry: VisibleFile, n: number, expected: number, manifest: OpenedManifest,
): Promise<Blob> {
  const header = new Uint8Array(file_header_length());
  let headerBytes = 0;
  let received = 0;
  let opened: ReturnType<OpenedManifest["decrypt_file_init"]> | undefined;
  const reader = (await downloadFile(id, n, grant)).getReader();
  const parts: Blob[] = [];
  function append(bytes: Uint8Array<ArrayBuffer>) {
    if (bytes.length) parts.push(new Blob([bytes]));
    bytes.fill(0);
  }
  try {
    for (let streamed = await reader.read(); !streamed.done; streamed = await reader.read()) {
      let bytes = streamed.value;
      received += bytes.length;
      if (received > expected) throw new Error("Could not decrypt the share.");
      if (!opened) {
        const take = Math.min(bytes.length, header.length - headerBytes);
        header.set(bytes.subarray(0, take), headerBytes);
        headerBytes += take;
        if (headerBytes < header.length) continue;
        opened = manifest.decrypt_file_init(n, header);
        bytes = bytes.subarray(take);
      }
      for (let offset = 0; offset < bytes.length; offset += sliceSize) {
        append(opened.update(bytes.subarray(offset, offset + sliceSize)));
      }
    }
    if (!opened || received !== expected) throw new Error("Could not decrypt the share.");
    const final = opened;
    opened = undefined;
    append(final.finish());
    return new Blob(parts, { type: supportedImage(entry.mime) ? entry.mime : "application/octet-stream" });
  } finally {
    opened?.free();
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

async function reveal(password: string | undefined): Promise<Revealed> {
  if (!recipient) throw new Error(unavailable);
  const { id, secret, hasPassword } = recipient;
  const exchange = secret.start(hasPassword ? password : undefined);
  let evaluated: string;
  try {
    ({ evaluated } = await evaluate(id, exchange.blinded()));
  } catch (error) {
    exchange.free();
    throw error;
  }
  const session = exchange.finish(evaluated, id);
  try {
    let usedView = false;
    try {
      const { manifest, files, grant, views_left: viewsLeft } = await openShare(id, session.access_tag(), () => {
        usedView = true;
        secret.free();
        recipient = undefined;
      });
      const opened = session.open_manifest(manifest, files.length);
      try {
        const content = JSON.parse(opened.visible_content()) as Content & { files: VisibleFile[] };
        const decrypted: Revealed["files"] = [];
        for (const { n, size } of files) {
          const entry = content.files[n];
          if (!entry) throw new Error("Could not decrypt the share.");
          const blob = await fetchFile(id, grant, entry, n, size, opened);
          decrypted.push({ ...entry, blob });
        }
        return { note: content.note, login: content.login, files: decrypted, viewsLeft };
      } finally {
        opened.free();
      }
    } catch (error) {
      if (!usedView) throw error;
      const detail = error instanceof ApiError ? ` ${error.message}` : " Ask the sender for a new link.";
      throw new UsedViewError(`A view was used, but the contents could not be read.${detail}`);
    }
  } finally {
    session.free();
  }
}

function reply(value: Reply) {
  scope.postMessage(value);
}

let processing = false;
scope.onmessage = async ({ data }: MessageEvent<Request>) => {
  const { id, operation, input } = data;
  if (processing) {
    reply({ id, error: "An action is in progress. Try again when it finishes.", usedView: false });
    return;
  }
  processing = true;
  try {
    await (ready ??= init());
    let result: Result;
    switch (operation) {
      case "create":
        result = await create(input, (progress) => reply({ id, progress }));
        break;
      case "remove":
        if (!owned) throw new Error(unavailable);
        result = true;
        try {
          await deleteShare(owned.id, owned.token.bearer());
        } catch (error) {
          if (!(error instanceof ApiError && error.code === "not_found")) throw error;
          result = false;
        }
        owned.token.free();
        owned = undefined;
        break;
      case "password":
        result = generate_password();
        break;
      case "load": {
        const parsed = shareId(input.path);
        if (!parsed) throw new Error(unavailable);
        let secret: LinkSecret;
        try {
          secret = LinkSecret.parse(input.path, input.fragment);
        } catch {
          throw new Error(unavailable);
        }
        try {
          const metadata = await getMetadata(parsed);
          recipient?.secret.free();
          recipient = { id: parsed, secret, hasPassword: metadata.has_password };
          result = metadata;
        } catch (error) {
          secret.free();
          throw error;
        }
        break;
      }
      case "reveal":
        result = await reveal(input.password);
        break;
    }
    reply({ id, result });
  } catch (error) {
    reply({ id, error: error instanceof Error ? error.message : "The action failed. Try again.",
      usedView: error instanceof UsedViewError,
      wrongPassword: operation === "reveal" && recipient?.hasPassword === true
        && error instanceof ApiError && error.code === "unauthorized" });
  } finally {
    processing = false;
  }
};
