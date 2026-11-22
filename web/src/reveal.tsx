import { For, Show, createSignal, flush, onCleanup } from "solid-js";
import { unavailable } from "./api";
import type { Metadata } from "./api";
import { CopyButton } from "./copy-field";
import { passwordError } from "./form-error";
import { Icon } from "./icons";
import { supportedImage } from "./image-types";
import { MaskedSecret } from "./masked-secret";
import { RollingCounter } from "./rolling-counter";
import { playSound } from "./share-sounds";
import { DecodedImage, TextReveal } from "./text-reveal";
import { ToastStack, createToasts } from "./toast-stack";
import { changeView, finishViewTransition, motionAllowed } from "./transitions";
import { Expiry, IconButton, fileSize, message } from "./ui";
import { WorkerError } from "./worker-client";
import type { CryptoClient } from "./worker-client";
import { loginFields } from "./worker-protocol";
import type { LoginField, Revealed, RevealedFile } from "./worker-protocol";

const fields = Object.keys(loginFields) as LoginField[];

function LoginValue(props: {
  field: LoginField; value: string; index: number; animate: boolean;
  feedback: (status: string, error?: boolean, pointer?: boolean) => void;
}) {
  const label = () => loginFields[props.field];
  const masked = () => props.field === "password" || props.field === "totp" ? props.field : undefined;
  return (
    <div class="field revealed-field" data-animate={props.animate ? "" : undefined} ref={(element) => {
      element.style.setProperty("--field-delay", `${props.index * 40}ms`);
    }}>
      <span>{label()}</span>
      <div class="input-row">
        <Show when={masked()} keyed fallback={<span class="secret mono">{props.value}</span>}>
          {(field) => <MaskedSecret field={field} label={label()} value={props.value} />}
        </Show>
        <CopyButton label={`Copy ${label().toLowerCase()}`} value={props.value} feedback={props.feedback} />
      </div>
    </div>
  );
}

function RevealedAttachment(props: { file: RevealedFile; animate: boolean }) {
  const url = URL.createObjectURL(props.file.blob);
  onCleanup(() => URL.revokeObjectURL(url));
  return (
    <li class="attachment">
      <Show when={supportedImage(props.file.mime)}>
        <DecodedImage src={url} name={props.file.name} orientation={props.file.orientation} animate={props.animate} />
      </Show>
      <div class="file-row">
        <div class="file-info"><span>{props.file.name}</span><small>{fileSize(props.file.size)}</small></div>
        <a class="icon-button" href={url} download={props.file.name}
          title={`Download ${props.file.name}`} aria-label={`Download ${props.file.name}`}>
          <Icon name="download" />
        </a>
      </div>
    </li>
  );
}

export function Reveal(props: { client: CryptoClient; path: string; takeFragment: () => string }) {
  const [metadata, setMetadata] = createSignal<Metadata>();
  const [opened, setOpened] = createSignal<Revealed>();
  const [password, setPassword] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal(false);
  const [invalid, setInvalid] = createSignal(false);
  const [animate, setAnimate] = createSignal(false);
  const [gone, setGone] = createSignal(false);
  const toasts = createToasts();
  const count = () => opened()?.viewsLeft ?? metadata()?.views_left;
  let field: HTMLInputElement | undefined;
  let panel: HTMLDivElement | undefined;
  let submitPointer = false;
  let departed = false;
  let closing = false;
  let stopDust: (() => void) | undefined;
  let revealing = false;

  function leave() {
    departed = true;
    stopDust?.();
    finishViewTransition();
    props.client.close();
    flush(() => {
      setOpened(undefined);
      setMetadata(undefined);
      setPassword("");
      setGone(true);
      setLoading(false);
    });
  }

  window.addEventListener("pagehide", leave);
  onCleanup(() => {
    departed = true;
    stopDust?.();
    window.removeEventListener("pagehide", leave);
  });

  void props.client.call("load", { path: props.path, fragment: props.takeFragment() })
    .then((share) => { if (!departed) setMetadata(share); }, (cause: unknown) => {
      if (!departed) toasts.notify(message(cause), true, false);
    }).finally(() => setLoading(false));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const pointer = submitPointer;
    submitPointer = false;
    const share = metadata();
    if (revealing || !share) return;
    revealing = true;
    const value = share.has_password ? password() : undefined;
    playSound("tap");
    try {
      await changeView("sealed", () => {
        toasts.notify("", true);
        setInvalid(false);
        setAnimate(motionAllowed(pointer));
        setBusy(true);
      }, pointer);
      if (departed) return;
      const content = await props.client.call("reveal", { password: value });
      if (departed) return;
      await changeView("reveal", () => {
        setAnimate(motionAllowed(pointer));
        setOpened(content);
        setMetadata(undefined);
        setPassword("");
        setBusy(false);
      }, pointer);
      if (!pointer) document.getElementById("reveal-title")?.focus({ preventScroll: true });
    } catch (cause) {
      if (departed) return;
      const problem = message(cause);
      const wrong = cause instanceof WorkerError && cause.wrongPassword;
      await changeView("error", () => {
        if (problem === unavailable || (cause instanceof WorkerError && cause.usedView)) {
          setMetadata(undefined);
          setPassword("");
        }
        setInvalid(wrong);
        setBusy(false);
        toasts.notify(problem, true, pointer);
      }, pointer);
      if (wrong) passwordError(field, pointer);
    } finally {
      revealing = false;
      setBusy(false);
    }
  }

  function closeLastView(event: MouseEvent) {
    if (closing || opened()?.viewsLeft !== 0 || !panel) return;
    closing = true;
    const pointer = event.detail > 0;
    playSound("dissolve");
    if (motionAllowed(pointer)) {
      const bounds = [...panel.querySelectorAll(".plain, .secret, .revealed-image, .file-row")]
        .map((element) => element.getBoundingClientRect());
      const began = performance.now();
      void import("./dust-delete").then(({ scatterDust }) => {
        if (!departed) stopDust = scatterDust(bounds, began);
      }).catch(() => undefined);
    }
    void changeView("burn", () => {
      setOpened(undefined);
      setGone(true);
      toasts.notify("");
      toasts.notify("", true);
    }, pointer).then(() => {
      if (!pointer) document.getElementById("share-gone")?.focus({ preventScroll: true });
    });
  }

  return (
    <section aria-labelledby="reveal-title">
      <h1 id="reveal-title" tabindex={-1}>Shared with you</h1>
      <Show when={loading()}><p class="secondary" role="status">Checking link…</p></Show>
      <Show when={count() !== undefined}>
        <p class="secondary share-meta">
          <Show when={metadata()} keyed>{(share) => <><Expiry seconds={share.expires_at} />. </>}</Show>
          <RollingCounter count={count() ?? 0} animate={animate()} />
        </p>
      </Show>
      <Show when={metadata()} keyed>{(share) => (
        <form onSubmit={submit} class="reveal-form reveal-panel">
          <div class="sealed-placeholder" aria-hidden="true"><Icon name="lock" /></div>
          <Show when={share.has_password}>
            <label class="field" for="reveal-password">
              <span>Share password</span>
              <input type="password" autocomplete="off" id="reveal-password" disabled={busy()}
                aria-invalid={invalid() ? "true" : "false"} ref={(element) => { field = element; }}
                value={password()} onInput={(event) => {
                  setPassword(event.currentTarget.value);
                  setInvalid(false);
                  toasts.notify("", true);
                }} />
            </label>
          </Show>
          <button class="primary" type="submit" disabled={busy()}
            onClick={(event) => { submitPointer = event.detail > 0; }}>{busy() ? "Revealing…" : "Reveal"}</button>
        </form>
      )}</Show>
      <Show when={opened()} keyed>{(content) => (
        <TextReveal capture={(element) => { panel = element; }}>
          <Show when={content.note !== undefined}><pre class="plain mono">{content.note}</pre></Show>
          <Show when={content.login} keyed>{(login) => (
            <div class="fields">
              <For each={fields.filter((field) => login[field] !== undefined)}>{(field, index) => (
                <LoginValue field={field} value={login[field] ?? ""} index={index()}
                  animate={animate()} feedback={toasts.notify} />
              )}</For>
            </div>
          )}</Show>
          <Show when={content.files.length > 0}>
            <ul class="file-list"><For each={content.files}>{(file) => (
              <RevealedAttachment file={file} animate={animate()} />
            )}</For></ul>
          </Show>
          <Show when={content.viewsLeft === 0}>
            <div class="last-view">
              <p class="secondary">This was the last view.</p>
              <IconButton icon="remove" label="Close share" onClick={closeLastView} />
            </div>
          </Show>
        </TextReveal>
      )}</Show>
      <Show when={gone()}>
        <p class="reveal-panel secondary" id="share-gone" role="status" tabindex={-1}>This share is gone.</p>
      </Show>
      <ToastStack toasts={toasts} />
    </section>
  );
}
