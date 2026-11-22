// Adapted from Bencho "Password strength" (bencho.dev), used under the Bencho Pro licence.
import { For, Show } from "solid-js";
import { Icon } from "./icons";

const rules = [
  { label: "At least 8 characters", test: (value: string) => value.length >= 8 },
  { label: "Upper and lower case", test: (value: string) => /[a-z]/.test(value) && /[A-Z]/.test(value) },
  { label: "A number", test: (value: string) => /\d/.test(value) },
  { label: "A symbol", test: (value: string) => /[^A-Za-z0-9\s]/.test(value) },
];
const words = ["Weak", "Weak", "Fair", "Good", "Strong"];

export function PasswordStrength(props: { value: string; change: (value: string) => void }) {
  const score = () => rules.filter((rule) => rule.test(props.value)).length;
  return (
    <div class="share-password">
      <label class="field" for="share-password">
        <span>Share password</span>
        <input id="share-password" type="password" autocomplete="new-password" spellcheck={false}
          value={props.value} onInput={(event) => props.change(event.currentTarget.value)}
          aria-describedby={props.value ? "share-strength" : undefined} />
      </label>
      <Show when={props.value}>
        <div class="strength">
          <div class="strength-meter">
            <div class="strength-bar" aria-hidden="true">
              <For each={rules}>{(_, index) => (
                <span><i data-met={index() < score() ? "" : undefined} /></span>
              )}</For>
            </div>
            <span id="share-strength" role="status">{words[score()]}</span>
          </div>
          <ul class="strength-rules">
            <For each={rules}>{(rule) => (
              <li data-met={rule.test(props.value) ? "" : undefined}>
                <Icon name="check" />
                <span class="visually-hidden">{rule.test(props.value) ? "Met. " : "Missing. "}</span>
                {rule.label}
              </li>
            )}</For>
          </ul>
        </div>
      </Show>
    </div>
  );
}
