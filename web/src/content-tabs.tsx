// Adapted from Bencho "Tab bar" (bencho.dev), used under the Bencho Pro licence.
import { For } from "solid-js";
import { Icon } from "./icons";
import { playSound } from "./share-sounds";
import { changeView } from "./transitions";

const labels = { text: "Text", login: "Login", files: "Files" } as const;
export type ContentKind = keyof typeof labels;
const tabs = Object.keys(labels) as ContentKind[];

export function ContentTabs(props: { value: ContentKind; select: (kind: ContentKind) => void }) {
  let wanted = tabs.indexOf(props.value);
  const buttons: HTMLButtonElement[] = [];

  function pick(kind: ContentKind, pointer: boolean) {
    const next = tabs.indexOf(kind);
    if (next === wanted) return;
    const direction = next > wanted ? "forward" : "back";
    wanted = next;
    if (pointer) playSound("tap");
    void changeView(direction, () => props.select(kind), pointer);
  }

  return (
    <div class="type-row content-tabs" role="tablist" aria-label="Content type" data-selected={props.value}>
      <span class="tab-indicator" data-motion-shared="" aria-hidden="true" />
      <For each={tabs}>{(kind, index) => (
        <button type="button" role="tab" class="icon-button content-tab" id={`tab-${kind}`}
          title={labels[kind]} aria-label={labels[kind]} aria-selected={props.value === kind ? "true" : "false"}
          aria-controls="compose-content" tabindex={props.value === kind ? 0 : -1}
          ref={(element) => { buttons[index()] = element; }}
          onClick={(event) => pick(kind, event.detail > 0)}
          onKeyDown={(event) => {
            const current = index();
            const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1
              : event.key === "ArrowRight" ? (current + 1) % tabs.length
                : event.key === "ArrowLeft" ? (current + tabs.length - 1) % tabs.length : -1;
            const target = tabs[next];
            if (!target) return;
            event.preventDefault();
            pick(target, false);
            buttons[next]?.focus();
          }}>
          <Icon name={kind} />
          <span class="tab-label" aria-hidden="true">{labels[kind]}</span>
        </button>
      )}</For>
    </div>
  );
}
