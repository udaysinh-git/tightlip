import { For, Show, createSignal, flush, onCleanup } from "solid-js";
import { unavailable } from "./api";
import type { Metadata } from "./api";
import { CopyButton } from "./copy-field";
import { createFeedback, Feedback } from "./feedback";
import { passwordError } from "./form-error";
import { Icon } from "./icons";
import { supportedImage } from "./image-types";
import { MaskedSecret } from "./masked-secret";
import { RollingCounter } from "./rolling-counter";
import { Seal, SealGlyph } from "./seal";
import { viewLabel } from "./sentence-choice";
import { playSound } from "./share-sounds";
import { DecodedImage, TextReveal } from "./text-reveal";
import { changeView, finishViewTransition, motionAllowed, paperDust } from "./transitions";
import { Expiry, IconButton, fileSize, message } from "./ui";
import { WorkerError } from "./worker-client";
import type { CryptoClient } from "./worker-client";
import { loginFields } from "./worker-protocol";
import type { LoginField, Revealed, RevealedFile } from "./worker-protocol";

const fields = Object.keys(loginFields) as LoginField[];

function LoginValue(props: {
  field: LoginField; value: string; feedback: ReturnType<typeof createFeedback>["notify"];
}) {
  const label = () => props.field === "totp" ? "TOTP" : loginFields[props.field];
  const masked = () => props.field === "password" || props.field === "totp" ? props.field : undefined;
  return (
    <div class="login-field revealed-field">
      <span>{label()}</span>
      <div class="input-row">
        <Show when={masked()} keyed fallback={<span class="secret">{props.value}</span>}>
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
  const [unread, setUnread] = createSignal(false);
  const [priorCount, setPriorCount] = createSignal(0);
  const [keyless, setKeyless] = createSignal(false);
  const feedback = createFeedback();
  let field: HTMLInputElement | undefined;
  let seal: HTMLSpanElement | undefined;
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
      feedback.notify("");
    });
  }

  window.addEventListener("pagehide", leave);
  onCleanup(() => {
    departed = true;
    stopDust?.();
    window.removeEventListener("pagehide", leave);
  });

  // The key lives only in the address fragment, which is removed on arrival. A reload has none.
  const fragment = props.takeFragment();
  if (!fragment) {
    setKeyless(true);
    setLoading(false);
  } else void props.client.call("load", { path: props.path, fragment })
    .then((share) => { if (!departed) setMetadata(share); }, (cause: unknown) => {
      if (departed) return;
      const problem = message(cause);
      if (problem === unavailable) setGone(true);
      else feedback.notify(problem, true);
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
      flush(() => {
        feedback.notify("");
        setInvalid(false);
        setBusy(true);
      });
      if (departed) return;
      const content = await props.client.call("reveal", { password: value });
      if (departed) return;
      if (seal && motionAllowed(pointer)) {
        seal.dataset.breaking = "";
        await Promise.allSettled(seal.getAnimations({ subtree: true }).map((animation) => animation.finished));
      }
      if (departed) return;
      await changeView("reveal", () => {
        setAnimate(motionAllowed(pointer));
        setPriorCount(share.views_left);
        setOpened(content);
        setMetadata(undefined);
        setPassword("");
        setBusy(false);
      }, pointer);
      if (!pointer) document.getElementById("revealed-paper")?.focus({ preventScroll: true });
    } catch (cause) {
      if (departed) return;
      const problem = message(cause);
      const attempts = cause instanceof WorkerError ? cause.attemptsLeft : undefined;
      const wrong = attempts !== undefined;
      flush(() => {
        if (attempts === 0 || problem === unavailable || (cause instanceof WorkerError && cause.usedView)) {
          setMetadata(undefined);
          setPassword("");
          if (cause instanceof WorkerError && cause.usedView) setUnread(true);
          else setGone(true);
        }
        setInvalid(wrong);
        setBusy(false);
        if (problem !== unavailable) feedback.notify(problem, true);
      });
      if (wrong && attempts !== 0) passwordError(field, pointer);
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
    stopDust = paperDust(panel, pointer);
    void changeView("burn", () => {
      setOpened(undefined);
      setGone(true);
      feedback.notify("");
    }, pointer).then(() => {
      if (!pointer) document.getElementById("share-gone")?.focus({ preventScroll: true });
    });
  }

  return (
    <section aria-label="Shared secret">
      <Show when={loading()}>
        <p class="paper folded-paper quiet-paper" role="status">Checking link…</p>
      </Show>
      <Show when={metadata()} keyed>{(share) => (
        <form class="reveal-form" onSubmit={submit}>
          <div class="paper folded-paper sealed-paper" data-motion-shared="">
            <Seal capture={(element) => { seal = element; }} />
            <div class="sealed-message">
              <p>Someone sealed this for you. {share.views_left === 1
                ? "It burns after this view." : `${viewLabel(share.views_left)} left.`}</p>
              <span class="visually-hidden"><Expiry seconds={share.expires_at} />.</span>
            </div>
            <Show when={share.has_password}>
              <label class="reveal-password" for="reveal-password">
                <span>Share password</span>
                <input type="password" autocomplete="off" spellcheck="false" autocorrect="off" autocapitalize="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" id="reveal-password" disabled={busy()}
                  aria-invalid={invalid() ? "true" : "false"} ref={(element) => { field = element; }}
                  value={password()} onInput={(event) => {
                    setPassword(event.currentTarget.value);
                    setInvalid(false);
                    feedback.notify("");
                  }} />
              </label>
            </Show>
          </div>
          <Feedback feedback={feedback} />
          <div class="primary-slot">
            <button class="primary" type="submit" disabled={busy()}
              onClick={(event) => { submitPointer = event.detail > 0; }}>
              <SealGlyph />{busy() ? "Opening…" : "Break the seal"}
            </button>
          </div>
        </form>
      )}</Show>
      <Show when={opened()} keyed>{(content) => (
        <>
          <div class="paper open-paper revealed-paper" id="revealed-paper" tabindex={-1}
            data-motion-shared="" ref={(element) => { panel = element; }}>
            <TextReveal>
              <Show when={content.note !== undefined}>
                <div class="note-row">
                  <pre class="plain">{content.note}</pre>
                  <CopyButton label="Copy text" value={content.note ?? ""} feedback={feedback.notify} />
                </div>
              </Show>
              <Show when={content.login} keyed>{(login) => (
                <div class="login-fields">
                  <For each={fields.filter((field) => login[field] !== undefined)}>{(field) => (
                    <LoginValue field={field} value={login[field] ?? ""} feedback={feedback.notify} />
                  )}</For>
                </div>
              )}</Show>
              <Show when={content.files.length > 0}>
                <ul class="file-list"><For each={content.files}>{(file) => (
                  <RevealedAttachment file={file} animate={animate()} />
                )}</For></ul>
              </Show>
              <Show when={content.failedFiles.length > 0}>
                <p role="status">A view was used. These files could not be read.</p>
                <ul><For each={content.failedFiles}>{(name) => <li>{name}</li>}</For></ul>
              </Show>
            </TextReveal>
          </div>
          <Show when={content.viewsLeft !== undefined}>
            <div class="reveal-meta">
              <p class="sentence" role="status"><Show when={content.viewsLeft === 0} fallback={
                <><RollingCounter count={content.viewsLeft ?? 0} previous={priorCount()} animate={animate()} />
                  {" "}{content.viewsLeft === 1 ? "view" : "views"} left.</>
              }>This was the last view.</Show></p>
              <Show when={content.viewsLeft === 0}>
                <IconButton icon="remove" label="Close share" onClick={closeLastView} />
              </Show>
            </div>
          </Show>
          <Feedback feedback={feedback} />
        </>
      )}</Show>
      <Show when={gone()}>
        <p class="paper folded-paper quiet-paper ash-paper" id="share-gone" role="status" tabindex={-1}
          data-motion-shared="">Nothing here. The link has burned or expired.</p>
      </Show>
      <Show when={keyless()}>
        <p class="paper folded-paper quiet-paper" role="status">This page no longer holds the key. Open the link you were sent again. Nothing has been used up.</p>
      </Show>
      <Show when={!metadata() && !opened() && !loading() && !keyless()}>
        <Show when={!gone() && !unread()}><p class="paper folded-paper quiet-paper">Could not check this link.</p></Show>
        <Feedback feedback={feedback} />
      </Show>
    </section>
  );
}
