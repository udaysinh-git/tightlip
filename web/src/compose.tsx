import { For, Show, createSignal, onCleanup } from "solid-js";
import type { CryptoClient } from "./worker-client";
import { Expiry, IconButton, message } from "./ui";
import { Icon } from "./icons";
import { ContentTabs } from "./content-tabs";
import type { ContentKind } from "./content-tabs";
import { CopyButton } from "./copy-field";
import { HoldDelete } from "./hold-delete";
import { PasswordStrength } from "./password-strength";
import { UploadAction } from "./upload-action";
import { UploadDropzone } from "./upload-dropzone";
import type { PickedFile } from "./upload-dropzone";
import { ToastStack, createToasts } from "./toast-stack";
import { changeView, isPointer } from "./transitions";
import { playSound } from "./share-sounds";
import { supportedImage } from "./image-types";
import { limits } from "./wire";
import { loginFields } from "./worker-protocol";
import type { Content, Created, Login, LoginField, Progress } from "./worker-protocol";

const loginKeys = Object.keys(loginFields) as LoginField[];
const expiryLabels: Record<number, string> = { 300: "5 minutes", 3600: "1 hour", 86400: "1 day",
  604800: "7 days", 2592000: "30 days" };

export function Compose(props: { client: CryptoClient }) {
  const [kind, setKind] = createSignal<ContentKind>("text");
  const [text, setText] = createSignal("");
  const [login, setLogin] = createSignal<Login>({});
  const [picked, setPicked] = createSignal<PickedFile[]>([]);
  const [ttl, setTtl] = createSignal(86400);
  const [views, setViews] = createSignal(1);
  const [passwordOpen, setPasswordOpen] = createSignal(false);
  const [password, setPassword] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [uploadPointer, setUploadPointer] = createSignal(false);
  const [progress, setProgress] = createSignal<Progress>();
  const [created, setCreated] = createSignal<Created>();
  const toasts = createToasts();
  const setError = (value: string) => toasts.notify(value, true);
  let nextFile = 0;
  let submitPointer = false;
  let creating = false;

  function clearFiles() {
    for (const { thumbnail } of picked()) {
      if (thumbnail) URL.revokeObjectURL(thumbnail);
    }
    setPicked([]);
  }

  onCleanup(clearFiles);

  function pick(files: FileList, pointer: boolean) {
    const incoming = Array.from(files);
    void changeView("files", () => {
      const old = picked();
      if (old.length + incoming.length > limits.files
        || [...old.map((item) => item.file), ...incoming].reduce((size, file) => size + file.size, 0)
          > limits.ciphertext) {
        setError("These files exceed the share limit. Pick up to 20 files totalling less than 100 MB.");
        return;
      }
      setError("");
      setPicked([...old, ...incoming.map((file) => ({
        id: ++nextFile, file, thumbnail: supportedImage(file.type) ? URL.createObjectURL(file) : undefined,
      }))]);
    }, pointer);
  }

  function removeFile(item: PickedFile, pointer: boolean) {
    void changeView("files", () => {
      if (item.thumbnail) URL.revokeObjectURL(item.thumbnail);
      setPicked((items) => items.filter((other) => other !== item));
      setError("");
    }, pointer);
  }

  function updateField(field: LoginField, value: string) {
    setLogin((previous) => ({ ...previous, [field]: value || undefined }));
    setError("");
  }

  function valid(): boolean {
    switch (kind()) {
      case "text": return text().length > 0;
      case "login": return Object.values(login()).some(Boolean);
      case "files": return picked().length > 0;
    }
  }

  async function generate() {
    if (creating) return;
    creating = true;
    setBusy(true);
    setError("");
    try {
      updateField("password", await props.client.call("password", undefined));
    } catch (cause) {
      setError(message(cause));
    } finally {
      creating = false;
      setBusy(false);
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const pointer = submitPointer;
    submitPointer = false;
    if (creating || !valid()) return;
    creating = true;
    const content: Content = kind() === "text" ? { note: text() }
      : kind() === "login" ? { login: login() } : {};
    const input = {
      content, files: kind() === "files" ? picked().map((item) => item.file) : [],
      ttl: ttl(), views: views(), password: passwordOpen() ? password() || undefined : undefined,
    };
    playSound("tap");
    try {
      await changeView("progress", () => {
        setBusy(true);
        setUploading(true);
        setUploadPointer(pointer);
        setError("");
        toasts.notify("");
        setProgress(undefined);
      }, pointer);
      const share = await props.client.call("create", input, setProgress);
      await changeView("link", () => {
        setCreated(share);
        setKind("text");
        setText("");
        setLogin({});
        setPassword("");
        setPasswordOpen(false);
        setTtl(86400);
        setViews(1);
        clearFiles();
      }, pointer);
      if (!pointer) document.getElementById("created-link")?.focus({ preventScroll: true });
    } catch (cause) {
      await changeView("progress", () => {
        setUploading(false);
        setBusy(false);
        toasts.notify(message(cause), true, pointer);
      }, pointer);
      if (!pointer) document.getElementById("create-link")?.focus({ preventScroll: true });
    } finally {
      setProgress(undefined);
      setUploading(false);
      creating = false;
      setBusy(false);
    }
  }

  async function removeShare(pointer: boolean) {
    if (creating) return;
    creating = true;
    setBusy(true);
    setError("");
    toasts.notify("");
    try {
      const deleted = await props.client.call("remove", undefined);
      await changeView("compose", () => {
        setCreated(undefined);
        setBusy(false);
        toasts.notify(deleted ? "Share deleted." : "This share is already unavailable.", false, pointer);
      }, pointer);
      if (!pointer) document.getElementById("tab-text")?.focus({ preventScroll: true });
    } catch (cause) {
      setError(message(cause));
    } finally {
      creating = false;
      setBusy(false);
    }
  }

  function startAgain(event: MouseEvent) {
    props.client.close();
    void changeView("compose", () => {
      setCreated(undefined);
      toasts.notify("");
      setError("");
    }, event.detail > 0).then(() => {
      if (event.detail === 0) document.getElementById("tab-text")?.focus({ preventScroll: true });
    });
  }

  return (
    <>
      <Show when={created()} keyed fallback={
        <section class="compose-view" aria-labelledby="compose-title">
          <h1 class="compose-heading" id="compose-title">New share</h1>
          <form onSubmit={submit}>
            <fieldset disabled={busy()}>
              <ContentTabs value={kind()} select={(value) => { setKind(value); setError(""); }} />
              <div class="content-area compose-content" id="compose-content" role="tabpanel"
                aria-labelledby={`tab-${kind()}`} data-motion-shared="">
                <Show when={kind() === "text"}>
                  <label class="field" for="share-text">
                    <span>Text</span>
                    <textarea id="share-text" class="mono" placeholder="Enter text to share"
                      spellcheck={false} value={text()} onInput={(event) => setText(event.currentTarget.value)} />
                  </label>
                </Show>
                <Show when={kind() === "login"}>
                  <div class="fields">
                    <For each={loginKeys}>{(field) => (
                      <div class="field">
                        <label for={`login-${field}`}>{loginFields[field]}</label>
                        <Show when={field === "note"} fallback={
                          <span class="input-row">
                            <input class="mono" id={`login-${field}`}
                              type={field === "password" ? "password" : "text"}
                              autocomplete={field === "password" ? "new-password" : "off"}
                              spellcheck={false} value={login()[field] ?? ""}
                              onInput={(event) => updateField(field, event.currentTarget.value)} />
                            <Show when={field === "password"}>
                              <IconButton icon="refresh" label="Generate password" onClick={() => void generate()} />
                            </Show>
                          </span>
                        }>
                          <textarea class="mono login-note" id={`login-${field}`} value={login()[field] ?? ""}
                            onInput={(event) => updateField(field, event.currentTarget.value)} />
                        </Show>
                      </div>
                    )}</For>
                  </div>
                </Show>
                <Show when={kind() === "files"}>
                  <UploadDropzone disabled={busy()} items={picked()} pick={pick} remove={removeFile} />
                </Show>
              </div>
              <div class="options">
                <label>Expiry
                  <span class="select-wrap expiry-choice">
                    <select onChange={(event) => {
                      const value = Number(event.currentTarget.value);
                      void changeView("expiry", () => setTtl(value), isPointer());
                    }}>
                      <option value="300">5 minutes</option>
                      <option value="3600">1 hour</option>
                      <option value="86400" selected>1 day</option>
                      <option value="604800">7 days</option>
                      <option value="2592000">30 days</option>
                    </select>
                    <span class="option-value" aria-hidden="true">{expiryLabels[ttl()]}</span>
                    <Icon name="chevron" />
                  </span>
                </label>
                <label>Views
                  <span class="select-wrap views-choice">
                    <select onChange={(event) => {
                      const value = Number(event.currentTarget.value);
                      void changeView("views", () => setViews(value), isPointer());
                    }}>
                      <option value="1" selected>1</option>
                      <option value="3">3</option>
                      <option value="10">10</option>
                    </select>
                    <span class="option-value" aria-hidden="true">{views()}</span>
                    <Icon name="chevron" />
                  </span>
                </label>
                <IconButton icon="lock" label="Share password" expanded={passwordOpen()} controls="share-password"
                  pressed={passwordOpen()} onClick={(event) => {
                    void changeView("password", () => setPasswordOpen((open) => !open), event.detail > 0)
                      .then(() => {
                        if (passwordOpen()) document.getElementById("share-password")?.focus({ preventScroll: true });
                      });
                  }} />
              </div>
              <Show when={passwordOpen()}>
                <PasswordStrength value={password()} change={setPassword} />
              </Show>
            </fieldset>
            <UploadAction work={uploading()} disabled={busy() || !valid()} progress={progress()}
              pointer={uploadPointer()} submitBy={(pointer) => { submitPointer = pointer; }} />
          </form>
        </section>
      }>{(share) => (
        <section class="compose-view" aria-labelledby="ready-title">
          <h1 class="compose-heading" id="ready-title">Link ready</h1>
          <div class="field compose-content link-field" data-motion-shared="">
            <label for="created-link">Share link</label>
            <span class="input-row">
              <input class="mono" readonly id="created-link" value={share.link} />
              <CopyButton label="Copy link" value={share.link} feedback={toasts.notify} />
            </span>
          </div>
          <p class="secondary"><Expiry seconds={share.expiresAt} />.</p>
          <div class="result-actions">
            <HoldDelete disabled={busy()} confirm={(pointer) => void removeShare(pointer)} />
            <IconButton icon="add" label="Create another share" disabled={busy()} onClick={startAgain} />
          </div>
          <p class="delete-help" id="delete-help">Hold Delete now to confirm.</p>
        </section>
      )}</Show>
      <ToastStack toasts={toasts} />
    </>
  );
}
