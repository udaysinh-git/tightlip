// Adapted from Bencho "Sweep button" (bencho.dev), used under the Bencho Pro licence.
// Adapted from Bencho "Pay button" (bencho.dev), used under the Bencho Pro licence.
import { Show, createRenderEffect } from "solid-js";
import type { Progress } from "./worker-protocol";

export function UploadAction(props: {
  work: boolean;
  disabled: boolean;
  progress?: Progress;
  pointer: boolean;
  submitBy: (pointer: boolean) => void;
}) {
  let fill: HTMLSpanElement | undefined;
  const fraction = () => {
    const status = props.progress;
    if (!status) return 0;
    const item = status.size ? Math.min(1, status.loaded / status.size) : 0;
    return (status.current - 1 + item) / status.total;
  };

  // Keep the fill attached to the rendered progress state, including its first frame.
  createRenderEffect(fraction, (value) => {
    fill?.style.setProperty("--upload-fraction", String(value));
  });

  const label = () => {
    const status = props.progress;
    if (!status) return "Preparing share…";
    if (status.phase === "encrypting") return `Encrypting file ${status.current}…`;
    if (status.current === status.total && status.loaded === status.size) return "Saving share…";
    const item = status.current === status.total ? "share details" : `file ${status.current}`;
    return `Uploading ${item}…`;
  };

  return (
    <div class="upload-slot">
      <Show when={props.work} fallback={
        <button class="primary upload-action" type="submit" id="create-link" disabled={props.disabled}
          onClick={(event) => props.submitBy(event.detail > 0)}>Create link</button>
      }>
        <div class="primary upload-action upload-meter" role="progressbar" aria-label={label()}
          aria-valuenow={Math.floor(fraction() * 100)} data-animate={props.pointer ? "" : undefined}>
          <span class="upload-fill" aria-hidden="true" ref={(element) => {
            fill = element;
            element.style.setProperty("--upload-fraction", String(fraction()));
          }} />
          <span class="upload-label">{label()}</span>
        </div>
      </Show>
    </div>
  );
}
