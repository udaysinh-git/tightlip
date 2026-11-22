// Adapted from Bencho "Password reveal" (bencho.dev), used under the Bencho Pro licence.
import { Show, createSignal } from "solid-js";
import { Icon } from "./icons";
import { changeView, motionAllowed } from "./transitions";

export function MaskedSecret(props: { field: "password" | "totp"; label: string; value: string }) {
  const [shown, setShown] = createSignal(false);
  const [animate, setAnimate] = createSignal(false);
  let intended = false;
  const label = () => `${shown() ? "Hide" : "Show"} ${props.label.toLowerCase()}`;

  function toggle(event: MouseEvent) {
    intended = !intended;
    const next = intended;
    const pointer = event.detail > 0;
    setAnimate(motionAllowed(pointer));
    void changeView(`secret-${props.field}`, () => setShown(next), pointer);
  }

  return (
    <>
      <span class="secret mono masked-secret" data-field={props.field}>
        <Show when={shown()} fallback={<span aria-label="Hidden">••••••••</span>}>{props.value}</Show>
      </span>
      <button class="icon-button eye-toggle" type="button" title={label()} aria-label={label()}
        aria-pressed={shown() ? "true" : "false"} data-shown={shown() ? "" : undefined}
        data-animate={animate() ? "" : undefined} onClick={toggle}>
        <span><Icon name="eye" /></span><span><Icon name="hide" /></span>
      </button>
    </>
  );
}
