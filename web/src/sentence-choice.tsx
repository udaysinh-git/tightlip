import { For, Show, createSignal, onCleanup } from "solid-js";
import { Icon } from "./icons";

export const viewLabel = (count: number) => `${count} ${count === 1 ? "view" : "views"}`;

export const viewChoices = [1, 3, 10].map((value) => ({ value, label: viewLabel(value) }));
export const expiryChoices = [
  { value: 300, label: "5 minutes" },
  { value: 3600, label: "1 hour" },
  { value: 86400, label: "1 day" },
  { value: 604800, label: "7 days" },
  { value: 2592000, label: "30 days" },
];

export function SentenceChoice(props: {
  id: string;
  label: string;
  choices: { value: number; label: string }[];
  value: number;
  change: (value: number) => void;
}) {
  const [open, setOpen] = createSignal(false);
  let group: HTMLSpanElement | undefined;
  let trigger: HTMLButtonElement | undefined;
  const selected = () => props.choices.find((choice) => choice.value === props.value);
  const outside = (event: PointerEvent) => {
    if (event.target instanceof Node && !group?.contains(event.target)) setOpen(false);
  };
  document.addEventListener("pointerdown", outside);
  onCleanup(() => document.removeEventListener("pointerdown", outside));

  function close() {
    setOpen(false);
    trigger?.focus({ preventScroll: true });
  }

  return (
    <span class="sentence-choice" data-choice={props.id} ref={(element) => { group = element; }}
      onFocusOut={(event) => {
        if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
      onKeyDown={(event) => {
        if (!open()) return;
        if (event.key === "Escape") {
          event.preventDefault();
          close();
          return;
        }
        const choices = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>(".choice-option"));
        const current = choices.indexOf(document.activeElement as HTMLButtonElement);
        const next = event.key === "Home" ? 0 : event.key === "End" ? choices.length - 1
          : event.key === "ArrowDown" ? (current + 1) % choices.length
          : event.key === "ArrowUp" ? (current < 0 ? choices.length - 1 : (current - 1 + choices.length) % choices.length)
          : undefined;
        if (next === undefined) return;
        event.preventDefault();
        choices[next]?.focus({ preventScroll: true });
      }}>
      <button class="sentence-button" type="button" aria-label={`${props.label}, ${selected()?.label}`}
        aria-expanded={open() ? "true" : "false"} aria-controls={open() ? props.id : undefined}
        ref={(element) => { trigger = element; }}
        onClick={() => setOpen((value) => !value)}>
        <span>{selected()?.label}</span><Icon name="chevron" />
      </button>
      <Show when={open()}>
        <span class="choice-popover" id={props.id} role="group" aria-label={props.label}>
          <For each={props.choices}>{(choice) => (
            <button class="choice-option" type="button" aria-pressed={choice.value === props.value ? "true" : "false"}
              onClick={() => { props.change(choice.value); close(); }}>
              {choice.label}
              {choice.value === props.value && <Icon name="check" />}
            </button>
          )}</For>
        </span>
      </Show>
    </span>
  );
}
