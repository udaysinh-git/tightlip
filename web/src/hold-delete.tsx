// Adapted from Bencho "Hold to delete" (bencho.dev), used under the Bencho Pro licence.
import { createSignal, onCleanup } from "solid-js";
import { motionAllowed } from "./transitions";

export function HoldDelete(props: { disabled: boolean; confirm: (pointer: boolean) => void }) {
  const [holding, setHolding] = createSignal(false);
  const [animate, setAnimate] = createSignal(false);
  const [confirmClick, setConfirmClick] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pointerId: number | undefined;
  let heldKey: string | undefined;

  function stop() {
    clearTimeout(timer);
    timer = undefined;
    pointerId = undefined;
    heldKey = undefined;
    setHolding(false);
  }

  function start(pointer: boolean) {
    if (timer !== undefined || props.disabled) return;
    setConfirmClick(false);
    setAnimate(motionAllowed(pointer));
    setHolding(true);
    timer = setTimeout(() => {
      stop();
      if (!props.disabled) props.confirm(pointer);
    }, 900);
  }

  function cancel() {
    stop();
    setConfirmClick(false);
  }

  function visibility() {
    if (document.visibilityState === "hidden") cancel();
  }

  document.addEventListener("visibilitychange", visibility);
  window.addEventListener("blur", cancel);
  onCleanup(() => {
    document.removeEventListener("visibilitychange", visibility);
    window.removeEventListener("blur", cancel);
    clearTimeout(timer);
  });

  return (
    <button type="button" class="quiet-button hold-delete" title="Press and hold to burn"
      aria-describedby="delete-help" disabled={props.disabled}
      data-holding={holding() ? "" : undefined} data-animate={animate() ? "" : undefined}
      onPointerDown={(event) => {
        if (event.button !== 0 || !event.isPrimary || timer !== undefined) return;
        pointerId = event.pointerId;
        if (event.isTrusted) event.currentTarget.setPointerCapture?.(event.pointerId);
        start(true);
      }}
      onPointerMove={(event) => {
        if (pointerId !== event.pointerId) return;
        const rect = event.currentTarget.getBoundingClientRect();
        if (event.clientX < rect.left || event.clientX > rect.right
          || event.clientY < rect.top || event.clientY > rect.bottom) stop();
      }}
      onPointerUp={(event) => { if (pointerId === event.pointerId) stop(); }}
      onPointerCancel={(event) => { if (pointerId === event.pointerId) stop(); }}
      onLostPointerCapture={(event) => { if (pointerId === event.pointerId) stop(); }}
      onKeyDown={(event) => {
        if (event.key !== " " && event.key !== "Enter") return;
        event.preventDefault();
        if (event.repeat || timer !== undefined) return;
        heldKey = event.key;
        start(false);
      }}
      onKeyUp={(event) => {
        if (event.key !== " " && event.key !== "Enter") return;
        event.preventDefault();
        if (heldKey === event.key) stop();
      }}
      onClick={(event) => {
        if (event.detail !== 0 || props.disabled) return;
        if (confirmClick()) { cancel(); props.confirm(false); }
        else setConfirmClick(true);
      }}
      onContextMenu={(event) => event.preventDefault()}
      onBlur={cancel}>
      {confirmClick() ? "Confirm burn" : "Burn now"}
      <span class="hold-fill" aria-hidden="true">Burn now</span>
    </button>
  );
}
