import { createSignal, onCleanup } from "solid-js";

export const sealedEvent = "tightlip:sealed";

// The wordmark's two i's carry wax drops for dots. They land on load, press on hover,
// and stamp again each time a note is sealed.
export function Logo() {
  const [stamping, setStamping] = createSignal(false);
  const stamp = () => setStamping(true);
  document.addEventListener(sealedEvent, stamp);
  onCleanup(() => document.removeEventListener(sealedEvent, stamp));
  return (
    <span class="wordmark" aria-hidden="true" data-stamp={stamping() ? "" : undefined}>
      t<span class="tittle">ı</span>ghtl<span class="tittle" onAnimationEnd={() => setStamping(false)}>ı</span>p
    </span>
  );
}
