import { For, Show, createSignal, flush, onCleanup } from "solid-js";
import type { CryptoClient } from "./worker-client";
import { Expiry, IconButton, message } from "./ui";
import { ContentTabs } from "./content-tabs";
import type { ContentKind } from "./content-tabs";
import { CopyButton } from "./copy-field";
import { createFeedback, Feedback } from "./feedback";
import { HoldDelete } from "./hold-delete";
import { PasswordStrength } from "./password-strength";
import { Seal } from "./seal";
import { expiryChoices, SentenceChoice, viewChoices, viewLabel } from "./sentence-choice";
import { UploadAction } from "./upload-action";
import { UploadDropzone } from "./upload-dropzone";
import type { PickedFile } from "./upload-dropzone";
import { changeView, paperDust } from "./transitions";
import { sealedEvent } from "./logo";
import { playSound } from "./share-sounds";
import { supportedImage } from "./image-types";
import { limits } from "./wire";
import { loginFields } from "./worker-protocol";
import type { Content, Created, Login, LoginField, Progress } from "./worker-protocol";

const loginKeys = Object.keys(loginFields) as LoginField[];

export function Compose(props: { client: CryptoClient }) {
  const [kind, setKind] = createSignal<ContentKind>("text");
  const [text, setText] = createSignal("");
  const [login, setLogin] = createSignal<Login>({});
  const [showLoginPassword, setShowLoginPassword] = createSignal(false);
  const [picked, setPicked] = createSignal<PickedFile[]>([]);
  const [ttl, setTtl] = createSignal(86400);
  const [views, setViews] = createSignal(1);
  const [passwordOpen, setPasswordOpen] = createSignal(false);
  const [password, setPassword] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [uploadPointer, setUploadPointer] = createSignal(false);
  const [progress, setProgress] = createSignal<Progress>();
  const [created, setCreated] = createSignal<Created & { ttl: number; views: number }>();
  const feedback = createFeedback();
  let submitPointer = false;
  let creating = false;
  let passwordField: HTMLInputElement | undefined;
  let folded: HTMLDivElement | undefined;
  let stopDust: (() => void) | undefined;

  function clearFiles() {
    for (const { thumbnail } of picked()) {
      if (thumbnail) URL.revokeObjectURL(thumbnail);
    }
    setPicked([]);
  }

  onCleanup(clearFiles);
  onCleanup(() => stopDust?.());

  function pick(files: FileList, pointer: boolean) {
    const incoming = Array.from(files);
    void changeView("files", () => {
      const old = picked();
      if (old.length + incoming.length > limits.files
        || [...old.map((item) => item.file), ...incoming].reduce((size, file) => size + file.size, 0)
          > limits.ciphertext) {
        feedback.notify("These files exceed the share limit. Pick up to 20 files totalling less than 100 MB.", true);
        return;
      }
      feedback.notify("");
      setPicked([...old, ...incoming.map((file) => ({
        file, thumbnail: supportedImage(file.type) ? URL.createObjectURL(file) : undefined,
      }))]);
    }, pointer);
  }

  function removeFile(item: PickedFile, pointer: boolean) {
    void changeView("files", () => {
      if (item.thumbnail) URL.revokeObjectURL(item.thumbnail);
      setPicked((items) => items.filter((other) => other !== item));
      feedback.notify("");
    }, pointer);
  }

  function updateField(field: LoginField, value: string) {
    setLogin((previous) => ({ ...previous, [field]: value || undefined }));
    feedback.notify("");
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
    feedback.notify("");
    try {
      updateField("password", await props.client.call("password", undefined));
    } catch (cause) {
      feedback.notify(message(cause), true);
    } finally {
      creating = false;
      flush(() => setBusy(false));
      document.getElementById("login-password")?.focus({ preventScroll: true });
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
      flush(() => {
        setBusy(true);
        setUploading(true);
        setUploadPointer(pointer);
        feedback.notify("");
        setProgress(undefined);
      });
      const share = await props.client.call("create", input, setProgress);
      await changeView("link", () => {
        setCreated({ ...share, ttl: input.ttl, views: input.views });
        setKind("text");
        setText("");
        setLogin({});
        setShowLoginPassword(false);
        setPassword("");
        setPasswordOpen(false);
        setTtl(86400);
        setViews(1);
        clearFiles();
      }, pointer);
      document.dispatchEvent(new Event(sealedEvent));
      if (!pointer) document.getElementById("created-link")?.focus({ preventScroll: true });
    } catch (cause) {
      flush(() => {
        setUploading(false);
        setBusy(false);
        feedback.notify(message(cause), true);
      });
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
    feedback.notify("");
    try {
      const deleted = await props.client.call("remove", undefined);
      if (deleted && folded) {
        playSound("dissolve");
        stopDust?.();
        stopDust = paperDust(folded, pointer);
      }
      await changeView(deleted ? "burn" : "compose", () => {
        setCreated(undefined);
        setBusy(false);
        feedback.notify(deleted ? "Share burned." : "This share is already unavailable.");
      }, pointer);
      if (!pointer) document.getElementById("share-text")?.focus({ preventScroll: true });
    } catch (cause) {
      feedback.notify(message(cause), true);
    } finally {
      creating = false;
      setBusy(false);
    }
  }

  function startAgain(event: MouseEvent) {
    props.client.close();
    void changeView("compose", () => {
      setCreated(undefined);
      feedback.notify("");
    }, event.detail > 0).then(() => {
      if (event.detail === 0) document.getElementById("share-text")?.focus({ preventScroll: true });
    });
  }

  function toggleSharePassword() {
    const open = !passwordOpen();
    flush(() => setPasswordOpen(open));
    if (open) passwordField?.focus({ preventScroll: true });
  }

  return (
    <Show when={created()} keyed fallback={
      <section aria-label="Compose a secret">
        <form onSubmit={submit}>
          <fieldset disabled={busy()}>
            <div class="paper open-paper compose-paper" id="compose-content" role="tabpanel"
              aria-labelledby={`tab-${kind()}`} data-kind={kind()} data-motion-shared="">
              <Show when={kind() === "text"}>
                <textarea id="share-text" class="note-text" aria-label="Secret text" placeholder="Write the secret here"
                  spellcheck={false} value={text()} onInput={(event) => {
                    setText(event.currentTarget.value);
                    feedback.notify("");
                  }} />
              </Show>
              <Show when={kind() === "login"}>
                <div class="login-fields">
                  <For each={loginKeys}>{(field) => (
                    <div class="login-field">
                      <label for={`login-${field}`}>{field === "totp" ? "TOTP" : loginFields[field]}</label>
                      <Show when={field === "note"} fallback={
                        <span class="input-row">
                          <input id={`login-${field}`}
                            type={field === "password" && !showLoginPassword() ? "password" : "text"}
                            autocomplete={field === "password" ? "new-password" : "off"}
                            spellcheck={false} value={login()[field] ?? ""}
                            onInput={(event) => updateField(field, event.currentTarget.value)} />
                          <Show when={field === "password"}>
                            <IconButton icon={showLoginPassword() ? "hide" : "eye"}
                              label={showLoginPassword() ? "Hide password" : "Show password"}
                              pressed={showLoginPassword()} onClick={() => setShowLoginPassword((shown) => !shown)} />
                            <IconButton icon="refresh" label="Generate password" onClick={() => void generate()} />
                          </Show>
                        </span>
                      }>
                        <textarea class="login-note" id={`login-${field}`} value={login()[field] ?? ""}
                          rows={1} onInput={(event) => updateField(field, event.currentTarget.value)} />
                      </Show>
                    </div>
                  )}</For>
                </div>
              </Show>
              <Show when={kind() === "files"}>
                <UploadDropzone disabled={busy()} items={picked()} pick={pick} remove={removeFile} />
              </Show>
            </div>
            <ContentTabs value={kind()} select={(value) => {
              setKind(value);
              setShowLoginPassword(false);
              feedback.notify("");
            }} />
          </fieldset>
          <div class="compose-foot">
            <fieldset class="sentence compose-options" disabled={busy()}>
              <span class="sentence-part">Burns after <SentenceChoice id="view-options" label="Views"
                choices={viewChoices} value={views()} change={setViews} /></span>{" "}
              <span class="sentence-part">or <SentenceChoice id="expiry-options" label="Expiry"
                choices={expiryChoices} value={ttl()} change={setTtl} />.</span>{" "}
              <button class="sentence-button password-toggle" type="button" onClick={toggleSharePassword}
                aria-expanded={passwordOpen() ? "true" : "false"}
                aria-controls={passwordOpen() ? "share-password-line" : undefined}>
                <span>{passwordOpen() ? "Remove password" : "Add a password"}</span>
              </button>{" "}
              <Show when={passwordOpen()}>
                <PasswordStrength value={password()} change={setPassword}
                  capture={(element) => { passwordField = element; }} />
              </Show>
            </fieldset>
            <UploadAction work={uploading()} busy={busy()} empty={!valid()} progress={progress()}
              pointer={uploadPointer()} submitBy={(pointer) => { submitPointer = pointer; }} />
          </div>
          <Feedback feedback={feedback} />
        </form>
      </section>
    }>{(share) => (
      <section aria-label="Sealed share">
        <div class="paper folded-paper result-paper" data-motion-shared="" ref={(element) => { folded = element; }}>
          <Seal />
          <div class="sealed-link">
            <input class="mono" readonly id="created-link" aria-label="Share link" value={share.link} />
            <CopyButton label="Copy link" value={share.link} feedback={feedback.notify} />
          </div>
        </div>
        <p class="sentence">Burns after {viewLabel(share.views)} or in{" "}
          <Expiry seconds={share.expiresAt} label={expiryChoices.find((choice) => choice.value === share.ttl)?.label} />.
          {" "}Only someone holding this link can read it.</p>
        <Feedback feedback={feedback} />
        <div class="result-actions">
          <button class="quiet-button" type="button" disabled={busy()} onClick={startAgain}>Seal another</button>
          <HoldDelete disabled={busy()} confirm={(pointer) => void removeShare(pointer)} />
          <CopyButton primary label="Copy link" value={share.link} feedback={feedback.notify} />
        </div>
        <span class="visually-hidden" id="delete-help">Hold Burn now to confirm.</span>
      </section>
    )}</Show>
  );
}
