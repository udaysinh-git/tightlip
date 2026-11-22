// Adapted from Bencho "Password strength" (bencho.dev), used under the Bencho Pro licence.
import { Show } from "solid-js";

const rules = [
  (value: string) => value.length >= 8,
  (value: string) => /[a-z]/.test(value) && /[A-Z]/.test(value),
  (value: string) => /\d/.test(value),
  (value: string) => /[^A-Za-z0-9\s]/.test(value),
];
const words = ["Weak", "Weak", "Fair", "Good", "Strong"];

export function PasswordStrength(props: {
  value: string; change: (value: string) => void; capture: (element: HTMLInputElement) => void;
}) {
  const score = () => rules.filter((rule) => rule(props.value)).length;
  return (
    <span class="share-password" id="share-password-line">
      <input id="share-password" type="password" aria-label="Share password" placeholder="Share password"
        autocomplete="new-password" spellcheck="false" autocorrect="off" autocapitalize="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" ref={props.capture}
        value={props.value} onInput={(event) => props.change(event.currentTarget.value)}
        aria-describedby={props.value ? "share-strength" : undefined} />
      <Show when={props.value}>
        <span class="strength-bar" data-strength={score()} aria-hidden="true" />
        <span id="share-strength" class="visually-hidden" role="status">Password strength: {words[score()]}</span>
      </Show>
    </span>
  );
}
