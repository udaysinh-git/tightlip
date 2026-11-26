import init, {
  LinkSecret, OwnerToken, file_header_length, generate_password, strip_image_metadata,
} from "tightlip-wasm/client";
import type { Draft, OpenedManifest, ShareSession } from "tightlip-wasm/client";
import {
  ApiError, NetworkError, commitShare, createShare, deleteShare, downloadFile, evaluate, getMetadata,
  openShare, retryNetwork, unavailable, uploadFile, uploadManifest,
} from "./api";
import { revealAttachment, safeFileName } from "./attachments";
import { scrubType } from "./image-types";
import { limits, shareId } from "./wire";
import type {
  Content, CreateInput, Created, Progress, Reply, Request, Result, Revealed, VisibleFile,
} from "./worker-protocol";

const scope = self as unknown as DedicatedWorkerGlobalScope;
const sliceSize = 64 * 1024;
let ready: ReturnType<typeof init> | undefined;
let owned: { id: string; token: OwnerToken } | undefined;
let recipient: { id: string; secret: LinkSecret; hasPassword: boolean; expiresAt: number } | undefined;

declare const __TIGHTLIP_WASM_INTEGRITY__: string;

async function loadWasm() {
  if (import.meta.env.DEV) return init();
  const url = new URL("../pkg/client/tightlip_bg.wasm", import.meta.url);
  const response = await fetch(url, { integrity: __TIGHTLIP_WASM_INTEGRITY__, redirect: "error" });
  if (!response.ok || response.headers.get("Content-Type") !== "application/wasm") {
    throw new Error("Could not load the encryption module.");
  }
  // wasm-bindgen passes the verified Response to WebAssembly.instantiateStreaming.
  return init({ module_or_path: response });
}

class UsedViewError extends Error {}
class WrongPasswordError extends Error {
  constructor(readonly attemptsLeft: number) {
    super(attemptsLeft === 0 ? "Wrong password. The share has burned."
      : `Wrong password. ${attemptsLeft} tries left before this burns.`);
  }
}

async function sealFile(session: ShareSession, draft: Draft, file: File): Promise<Blob> {
  let source: Blob = file;
  let orientation: number | undefined;
  const mime = scrubType(new Uint8Array(await file.slice(0, 12).arrayBuffer()));
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
        created = await createShare(
          exchange.blinded(), linkSecret.eval_verifier(), input.ttl, input.views, input.password !== undefined,
        );
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

class Download {
  readonly #header = new Uint8Array(file_header_length());
  readonly #chunk = new Uint8Array(sliceSize + 16);
  readonly #parts: Blob[] = [];
  #offset = 0;
  #opened: ReturnType<OpenedManifest["decrypt_file_init"]> | undefined;

  constructor(readonly n: number, readonly size: number, readonly entry: VisibleFile) {}

  free() {
    this.#opened?.free();
    this.#opened = undefined;
    this.#parts.length = 0;
  }

  #append(bytes: Uint8Array<ArrayBuffer>) {
    if (bytes.length) this.#parts.push(new Blob([bytes]));
    bytes.fill(0);
  }

  async read(id: string, grant: string, deadline: number, manifest: OpenedManifest) {
    if (Date.now() >= deadline) throw new NetworkError();
    const signal = AbortSignal.timeout(Math.max(1, deadline - Date.now()));
    const reader = (await downloadFile(id, this.n, grant, this.#offset, this.size, signal)).getReader();
    // A failed request discards the partial block and resumes at #offset.
    let buffered = 0;
    try {
      while (this.#offset < this.size) {
        const item = await reader.read().catch(() => { throw new NetworkError(); });
        if (item.done) throw new NetworkError();
        let bytes = item.value;
        while (bytes.length) {
          if (this.#offset >= this.size) throw new Error("Could not decrypt the share.");
          const block = this.#opened ? this.#chunk : this.#header;
          const required = Math.min(block.length, this.size - this.#offset);
          const take = Math.min(required - buffered, bytes.length);
          block.set(bytes.subarray(0, take), buffered);
          buffered += take;
          bytes = bytes.subarray(take);
          if (buffered !== required) continue;
          if (this.#opened) this.#append(this.#opened.update(block.subarray(0, required)));
          else this.#opened = manifest.decrypt_file_init(this.n, this.#header);
          this.#offset += required;
          buffered = 0;
        }
      }
      const opened = this.#opened;
      if (!opened) throw new Error("Could not decrypt the share.");
      this.#opened = undefined;
      this.#append(opened.finish());
      return await revealAttachment(this.entry, this.#parts);
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }
}

class Downloads {
  readonly #done = new Map<number, Revealed["files"][number]>();
  readonly #failed: string[] = [];
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(readonly id: string, readonly grant: string, readonly deadline: number,
    readonly manifest: OpenedManifest, readonly pending: Download[]) {}

  free() {
    clearTimeout(this.#timer);
    for (const job of this.pending) job.free();
    this.manifest.free();
  }

  async read(): Promise<Pick<Revealed, "files" | "failedFiles" | "retryUntil">> {
    clearTimeout(this.#timer);
    const next: Download[] = [];
    for (const job of this.pending) {
      try {
        const file = await retryNetwork(
          () => job.read(this.id, this.grant, this.deadline, this.manifest), this.deadline,
        );
        this.#done.set(job.n, file);
        job.free();
      } catch (error) {
        if (error instanceof NetworkError && Date.now() < this.deadline) next.push(job);
        else {
          this.#failed.push(safeFileName(job.entry.name));
          job.free();
        }
      }
    }
    this.pending.splice(0, this.pending.length, ...next);
    const retryUntil = next.length && Date.now() < this.deadline ? this.deadline : undefined;
    const result = {
      files: [...this.#done.entries()].sort(([a], [b]) => a - b).map(([, file]) => file),
      failedFiles: [...this.#failed, ...next.map((job) => safeFileName(job.entry.name))],
      retryUntil,
    };
    if (retryUntil) {
      pendingDownloads = this;
      this.#timer = setTimeout(() => {
        if (pendingDownloads === this) pendingDownloads = undefined;
        this.free();
      }, retryUntil - Date.now());
    } else {
      if (pendingDownloads === this) pendingDownloads = undefined;
      this.free();
    }
    return result;
  }
}

let pendingDownloads: Downloads | undefined;

async function reveal(password: string | undefined): Promise<Revealed> {
  if (!recipient) throw new Error(unavailable);
  const { id, secret, hasPassword, expiresAt } = recipient;
  const exchange = secret.start(hasPassword ? password : undefined);
  let evaluation: Awaited<ReturnType<typeof evaluate>>;
  try {
    evaluation = await evaluate(id, exchange.blinded(), secret.eval_tag());
  } catch (error) {
    exchange.free();
    if (error instanceof ApiError && error.code === "unauthorized") throw new Error(unavailable);
    throw error;
  }
  const session = exchange.finish(evaluation.evaluated, id);
  try {
    let usedView = false;
    try {
      const grantDeadline = Math.min(expiresAt * 1000, Date.now() + limits.grantSeconds * 1000);
      const { manifest, files, grant, views_left: viewsLeft } = await openShare(id, session.access_tag(), () => {
        if (!usedView) {
          usedView = true;
          secret.free();
          recipient = undefined;
        }
      });
      const opened = session.open_manifest(manifest, files.length);
      let content: Content & { files: VisibleFile[] };
      let jobs: Download[];
      try {
        content = JSON.parse(opened.visible_content()) as Content & { files: VisibleFile[] };
        jobs = files.map(({ n, size }) => {
          const entry = content.files[n];
          if (!entry) throw new Error("Could not decrypt the share.");
          return new Download(n, size, entry);
        });
      } catch (error) {
        opened.free();
        throw error;
      }
      const downloads = new Downloads(id, grant, grantDeadline, opened, jobs);
      return { note: content.note, login: content.login, viewsLeft, ...await downloads.read() };
    } catch (error) {
      if (!usedView) {
        if (hasPassword && error instanceof ApiError && error.code === "unauthorized") {
          if (evaluation.attempts_left === 0) {
            secret.free();
            recipient = undefined;
          }
          throw new WrongPasswordError(evaluation.attempts_left);
        }
        if (error instanceof NetworkError) {
          secret.free();
          recipient = undefined;
          throw new UsedViewError("The server may have used a view. The connection failed before the contents could be read.");
        }
        throw error;
      }
      const detail = error instanceof ApiError ? ` ${error.message}` : " Ask the sender for a new link.";
      throw new UsedViewError(`A view was used. The contents could not be read.${detail}`);
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
    await (ready ??= loadWasm());
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
          const metadata = await getMetadata(parsed, secret.eval_tag());
          recipient?.secret.free();
          recipient = { id: parsed, secret, hasPassword: metadata.has_password, expiresAt: metadata.expires_at };
          result = metadata;
        } catch (error) {
          secret.free();
          if (error instanceof ApiError && error.code === "unauthorized") {
            throw new Error("The key does not match this share. Check the key or ask for a new link.");
          }
          throw error;
        }
        break;
      }
      case "reveal":
        result = await reveal(input.password);
        break;
      case "retryDownload":
        if (!pendingDownloads) throw new Error("The download window has ended.");
        result = await pendingDownloads.read();
        break;
    }
    reply({ id, result });
  } catch (error) {
    reply({ id, error: error instanceof Error ? error.message : "The action failed. Try again.",
      usedView: error instanceof UsedViewError,
      attemptsLeft: error instanceof WrongPasswordError ? error.attemptsLeft : undefined });
  } finally {
    processing = false;
  }
};
