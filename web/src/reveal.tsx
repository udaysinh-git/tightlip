import { For, Show, createSignal, flush, onCleanup } from "solid-js";
import { unavailable } from "./api";
import type { Metadata } from "./api";
import { CopyButton } from "./copy-field";
import { createFeedback, Feedback } from "./feedback";
import { passwordError } from "./form-error";
import { Icon } from "./icons";
import { MaskedSecret } from "./masked-secret";
import { RollingCounter } from "./rolling-counter";
import { Seal, SealGlyph } from "./seal";
import { viewLabel } from "./sentence-choice";
import { playSound } from "./share-sounds";
import { DecodedImage, TextReveal } from "./text-reveal";
import { changeView, finishViewTransition, motionAllowed, paperDust } from "./transitions";
import { Expiry, FileName, IconButton, fileSize, message } from "./ui";
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
  const download = URL.createObjectURL(props.file.download);
  const preview = props.file.preview && URL.createObjectURL(props.file.preview);
  onCleanup(() => {
    URL.revokeObjectURL(download);
    if (preview) URL.revokeObjectURL(preview);
  });
  return (
    <li class="attachment">
      <Show when={preview} keyed>{(url) =>
        <DecodedImage src={url} name={props.file.name} orientation={props.file.orientation} animate={props.animate} />
      }</Show>
      <div class="file-row">
        <div class="file-info"><FileName name={props.file.name} />
          <small>{fileSize(props.file.size)}</small></div>
        <a class="icon-button" href={download} download={props.file.name}
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
  const [canRetry, setCanRetry] = createSignal(false);
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  function showDownloads(content: Revealed) {
    setOpened(content);
    clearTimeout(retryTimer);
    setCanRetry(content.retryUntil !== undefined && content.retryUntil > Date.now());
    if (content.retryUntil) retryTimer = setTimeout(() => setCanRetry(false), content.retryUntil - Date.now());
  }
  const [password, setPassword] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal(false);
  const [invalid, setInvalid] = createSignal(false);
  const [animate, setAnimate] = createSignal(false);
  const [gone, setGone] = createSignal(false);
  const [unread, setUnread] = createSignal(false);
  const [priorCount, setPriorCount] = createSignal(0);
  const [keyless, setKeyless] = createSignal(false);
  const [linkKey, setLinkKey] = createSignal("");
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
    clearTimeout(retryTimer);
    stopDust?.();
    finishViewTransition();
    props.client.close();
    flush(() => {
      setOpened(undefined);
      setMetadata(undefined);
      setPassword("");
      setLinkKey("");
      setGone(true);
      setLoading(false);
      feedback.notify("");
    });
  }

  window.addEventListener("pagehide", leave);
  onCleanup(() => {
    departed = true;
    clearTimeout(retryTimer);
    stopDust?.();
    window.removeEventListener("pagehide", leave);
  });

  async function load(fragment: string, pasted = false) {
    setLoading(true);
    feedback.notify("");
    try {
      const share = await props.client.call("load", { path: props.path, fragment });
      if (departed) return;
      setMetadata(share);
      setKeyless(false);
      setLinkKey("");
    } catch (cause) {
      if (departed) return;
      const problem = message(cause);
      if (!pasted && problem === unavailable) setGone(true);
      else feedback.notify(problem, true);
    } finally {
      setLoading(false);
    }
  }

  const fragment = props.takeFragment();
  if (fragment) void load(fragment);
  else {
    setKeyless(true);
    setLoading(false);
  }

  function submitKey(event: SubmitEvent) {
    event.preventDefault();
    if (loading()) return;
    const key = linkKey().trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(key)) {
      feedback.notify("Enter the 43-character share key.", true);
      return;
    }
    void load(key, true);
  }

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
        showDownloads(content);
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

  async function retryDownload() {
    const content = opened();
    if (!content || !canRetry() || busy()) return;
    setBusy(true);
    feedback.notify("");
    try {
      const files = await props.client.call("retryDownload", undefined);
      if (!departed && opened() === content) showDownloads({ ...content, ...files });
    } catch (cause) {
      if (!departed) feedback.notify(message(cause), true);
    } finally {
      setBusy(false);
    }
  }

  function closeLastView(event: MouseEvent) {
    if (closing || busy() || opened()?.viewsLeft !== 0 || !panel) return;
    closing = true;
    const pointer = event.detail > 0;
    playSound("dissolve");
    stopDust = paperDust(panel, pointer);
    void changeView("burn", () => {
      props.client.close();
      clearTimeout(retryTimer);
      setCanRetry(false);
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
                <ul><For each={content.failedFiles}>{(name) => <li><FileName name={name} /></li>}</For></ul>
                <Show when={canRetry()}>
                  <IconButton icon="refresh" label="Retry download" disabled={busy()} onClick={() => void retryDownload()} />
                </Show>
              </Show>
            </TextReveal>
          </div>
          <Show when={content.viewsLeft !== undefined}>
            <div class="reveal-meta">
              <p class="sentence" role="status"><Show when={content.viewsLeft === 0} fallback={
                <><RollingCounter count={content.viewsLeft ?? 0} previous={priorCount()} animate={animate()} />
                  {" "}{content.viewsLeft === 1 ? "view" : "views"} left.</>
              }>This was the last view.{content.files.length + content.failedFiles.length > 0
                ? " The server keeps the files for up to 10 minutes so downloads can finish, then deletes them."
                : ""}</Show></p>
              <Show when={content.viewsLeft === 0}>
                <IconButton icon="remove" label="Close share" disabled={busy()} onClick={closeLastView} />
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
        <form class="paper folded-paper quiet-paper share-key-form" onSubmit={submitKey}>
          <label class="reveal-password" for="reveal-key">
            <span>Share key</span>
            <input type="password" id="reveal-key" autocomplete="off" spellcheck="false" autocorrect="off"
              autocapitalize="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false"
              data-lt-active="false" placeholder="Paste the 43-character key" value={linkKey()}
              onInput={(event) => setLinkKey(event.currentTarget.value)} required />
          </label>
          <button class="primary" type="submit" disabled={loading()}>Use key</button>
          <Feedback feedback={feedback} />
        </form>
      </Show>
      <Show when={!metadata() && !opened() && !loading() && !keyless()}>
        <Show when={!gone() && !unread()}><p class="paper folded-paper quiet-paper">Could not check this link.</p></Show>
        <Feedback feedback={feedback} />
      </Show>
    </section>
  );
}
