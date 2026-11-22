// Adapted from Bencho "Form error" (bencho.dev), used under the Bencho Pro licence.
import { enter, motionAllowed } from "./transitions";

const shakes = new WeakMap<HTMLElement, Animation>();

export function passwordError(field: HTMLInputElement | undefined, pointer: boolean) {
  if (!field) return;
  field.focus({ preventScroll: true });
  shakes.get(field)?.cancel();
  if (!motionAllowed(pointer) || typeof field.animate !== "function") return;
  const frames = [0, -4, 4, -4, 4, 0].map((offset) => ({ transform: `translateX(${offset}px)`, easing: enter }));
  shakes.set(field, field.animate(frames, { duration: 250 }));
}
