// Adapted from Bencho "Copy field" (bencho.dev), used under the Bencho Pro licence.
import { createSignal, onCleanup } from "solid-js";
import { motionAllowed } from "./transitions";
import { playSound, prepareSound } from "./share-sounds";

export function CopyButton(props: {
  label: string;
  value: string;
  feedback: (text: string, error?: boolean, pointer?: boolean) => void;
}) {
  const [copied, setCopied] = createSignal(false);
  const [animate, setAnimate] = createSignal(false);
  let reset: ReturnType<typeof setTimeout> | undefined;
  let attempt = 0;
  onCleanup(() => { attempt += 1; clearTimeout(reset); });

  async function copy(event: MouseEvent) {
    const request = ++attempt;
    const pointer = event.detail > 0;
    prepareSound();
    try {
      await navigator.clipboard.writeText(props.value);
      if (request !== attempt) return;
      clearTimeout(reset);
      setAnimate(motionAllowed(pointer));
      setCopied(true);
      playSound("copied");
      props.feedback("Copied.", false, pointer);
      reset = setTimeout(() => setCopied(false), 1200);
    } catch {
      if (request === attempt) props.feedback("Could not copy. Select the value and copy it directly.", true, pointer);
    }
  }

  return (
    <button type="button" class="icon-button copy-button" aria-label={props.label} title={props.label}
      data-copied={copied() ? "" : undefined} data-animate={animate() ? "" : undefined}
      onClick={(event) => void copy(event)}>
      <svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none"
        stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
        <g class="copy-pages">
          <rect x="8" y="8" width="14" height="14" rx="2" />
          <path class="copy-back" d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
        </g>
        <path class="copy-check" d="m20 6-11 11-5-5" />
      </svg>
    </button>
  );
}
