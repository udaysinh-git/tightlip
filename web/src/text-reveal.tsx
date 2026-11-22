// Adapted from Bencho "Text blur" (bencho.dev), used under the Bencho Pro licence.
import { createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

export function TextReveal(props: { children: JSX.Element }) {
  return <div class="revealed-content">{props.children}</div>;
}

export function DecodedImage(props: { src: string; name: string; orientation?: number; animate: boolean }) {
  const [decoded, setDecoded] = createSignal(false);
  const [failed, setFailed] = createSignal(false);

  function decode(image: HTMLImageElement) {
    if (typeof image.decode !== "function") {
      setDecoded(true);
      return;
    }
    void image.decode().then(() => setDecoded(true), () => {
      // Some formats do not support decode(), even if load succeeds.
      if (image.complete && image.naturalWidth > 0) setDecoded(true);
    });
  }

  return (
    <div class={(props.orientation ?? 1) >= 5 ? "image-frame image-rotated" : "image-frame"}
      hidden={failed()}>
      <img class="revealed-image" data-orientation={props.orientation}
        data-decoded={decoded() ? "" : undefined} data-animate={props.animate ? "" : undefined}
        src={props.src} alt={props.name} decoding="async"
        onLoad={(event) => decode(event.currentTarget)} onError={() => setFailed(true)} />
    </div>
  );
}
