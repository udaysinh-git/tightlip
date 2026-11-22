// Adapted from Bencho "Password strength" (bencho.dev), used under the Bencho Pro licence.
import { Show, createSignal } from "solid-js";
import { IconButton } from "./ui";

const words = ["Weak", "Weak", "Fair", "Good", "Strong"];

export function passwordScore(password: string): number {
  const value = password.normalize("NFKC");
  const characters = Array.from(value);
  const length = characters.length;
  const alphabet = (/[a-z]/.test(value) ? 26 : 0) + (/[A-Z]/.test(value) ? 26 : 0)
    + (/\d/.test(value) ? 10 : 0) + (/[^a-zA-Z0-9]/.test(value) ? 33 : 0);
  const bits = length * Math.log2(Math.max(1, alphabet));
  if (length < 12 || new Set(characters).size < 4 || bits < 40) return length ? 1 : 0;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

export function PasswordStrength(props: {
  value: string; change: (value: string) => void; capture: (element: HTMLInputElement) => void;
  generate: () => void;
}) {
  const [shown, setShown] = createSignal(false);
  const score = () => passwordScore(props.value);
  return (
    <span class="share-password" id="share-password-line">
      <span class="input-row">
        <input id="share-password" type={shown() ? "text" : "password"} aria-label="Share password" placeholder="Share password"
          autocomplete="new-password" spellcheck="false" autocorrect="off" autocapitalize="off" data-gramm="false"
          data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" ref={props.capture}
          value={props.value} onInput={(event) => props.change(event.currentTarget.value)}
          aria-describedby={props.value ? "share-strength" : undefined} />
        <IconButton icon={shown() ? "hide" : "eye"} label={shown() ? "Hide share password" : "Show share password"}
          pressed={shown()} onClick={() => setShown((value) => !value)} />
        <IconButton icon="refresh" label="Generate share password" onClick={props.generate} />
      </span>
      <Show when={props.value}>
        <span class="strength-bar" data-strength={score()} aria-hidden="true" />
        <span id="share-strength" class="visually-hidden" role="status">Estimated password strength: {words[score()]}</span>
      </Show>
    </span>
  );
}
