// Adapted from Bencho "Sweep button" (bencho.dev), used under the Bencho Pro licence.
import { Show } from "solid-js";
import { SealGlyph } from "./seal";
import type { Progress } from "./worker-protocol";

export function UploadAction(props: {
  work: boolean;
  busy: boolean;
  empty: boolean;
  progress?: Progress;
  pointer: boolean;
  submitBy: (pointer: boolean) => void;
}) {
  const fraction = () => {
    const status = props.progress;
    if (!status) return 0;
    const item = status.size ? Math.min(1, status.loaded / status.size) : 0;
    return (status.current - 1 + item) / status.total;
  };

  const label = () => {
    const status = props.progress;
    if (!status) return "Preparing share…";
    if (status.phase === "encrypting") return `Encrypting file ${status.current}…`;
    if (status.current === status.total && status.loaded === status.size) return "Saving share…";
    const item = status.current === status.total ? "share details" : `file ${status.current}`;
    return `Uploading ${item}…`;
  };

  return (
    <div class="primary-slot">
      <Show when={props.work} fallback={
        <button class="primary upload-action" type="submit" id="create-link" disabled={props.busy}
          aria-disabled={props.empty ? "true" : undefined} title={props.empty ? "Write something first" : undefined}
          onClick={(event) => {
            if (props.empty) event.preventDefault();
            else props.submitBy(event.detail > 0);
          }}>
          <SealGlyph />Seal and get link
        </button>
      }>
        <div class="primary upload-action upload-meter" role="progressbar" aria-label={label()}
          aria-valuenow={Math.floor(fraction() * 100)} data-animate={props.pointer ? "" : undefined}>
          <svg class="upload-fill" viewBox="0 0 1 1" preserveAspectRatio="none" aria-hidden="true">
            <rect width="1" height="1" transform={`scale(${fraction()} 1)`} />
          </svg>
          <SealGlyph /><span>{label()}</span>
        </div>
      </Show>
    </div>
  );
}
