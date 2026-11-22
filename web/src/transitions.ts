import { flush } from "solid-js";

export const enter = "cubic-bezier(0.22, 1, 0.36, 1)";
const move = "cubic-bezier(0.25, 1, 0.5, 1)";
type Moment = "forward" | "back" | "files" | "link" | "compose" | "reveal" | "burn"
  | "secret-password" | "secret-totp";

interface Running {
  transition: ViewTransition;
  apply: () => void;
}

let active: Running | undefined;

export function motionAllowed(pointer = true): boolean {
  return pointer && typeof document.startViewTransition === "function"
    && !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

export function trackInput(): () => void {
  const root = document.documentElement;
  if (typeof document.startViewTransition === "function") root.dataset.motionSupported = "";
  const pointer = () => { root.dataset.input = "pointer"; };
  const keyboard = () => { root.dataset.input = "keyboard"; };
  document.addEventListener("pointerdown", pointer, true);
  document.addEventListener("keydown", keyboard, true);
  return () => {
    document.removeEventListener("pointerdown", pointer, true);
    document.removeEventListener("keydown", keyboard, true);
  };
}

export function isPointer(): boolean {
  return document.documentElement.dataset.input === "pointer";
}

function sharedPositions(): Map<string, DOMRect> {
  const positions = new Map<string, DOMRect>();
  for (const element of document.querySelectorAll("[data-motion-shared]")) {
    const name = getComputedStyle(element).viewTransitionName;
    if (name && name !== "none") positions.set(name, element.getBoundingClientRect());
  }
  return positions;
}

function interrupt() {
  if (!active) return;
  const previous = active;
  active = undefined;
  previous.transition.skipTransition();
  delete document.documentElement.dataset.motion;
  return previous;
}

export function finishViewTransition() {
  interrupt()?.apply();
}

export function paperDust(paper: HTMLElement, pointer: boolean): () => void {
  if (!motionAllowed(pointer)) return () => undefined;
  const bounds = paper.getBoundingClientRect();
  const began = performance.now();
  let cancelled = false;
  let stop: (() => void) | undefined;
  void import("./dust-delete").then(({ scatterDust }) => {
    if (!cancelled) stop = scatterDust(bounds, began);
  }).catch(() => undefined);
  return () => {
    cancelled = true;
    stop?.();
  };
}

export function changeView(moment: Moment, update: () => void, pointer: boolean): Promise<void> {
  const previous = interrupt();
  let applied = false;
  const apply = () => {
    if (applied) return;
    applied = true;
    // Preserve pending updates inside the new callback even if callbacks arrive out of order.
    previous?.apply();
    update();
    flush();
  };
  const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const crossfade = reduced && ["link", "compose", "reveal", "burn"].includes(moment);
  const supported = typeof document.startViewTransition === "function";
  if (!supported || (!crossfade && !motionAllowed(pointer)) || document.visibilityState === "hidden") {
    apply();
    return Promise.resolve();
  }

  const root = document.documentElement;
  root.dataset.motion = moment;
  const start = crossfade ? new Map<string, DOMRect>() : sharedPositions();
  let transition: ViewTransition;
  try {
    transition = document.startViewTransition(apply);
  } catch {
    delete root.dataset.motion;
    apply();
    return Promise.resolve();
  }
  active = { transition, apply };
  const clear = () => {
    if (active?.transition !== transition) return;
    active = undefined;
    delete root.dataset.motion;
  };
  void transition.finished.then(clear, clear);
  void transition.ready.then(() => {
    if (active?.transition !== transition || !motionAllowed()) return;
    for (const [name, end] of sharedPositions()) {
      const first = start.get(name);
      if (!first || !end.width || !end.height) continue;
      if (first.x === end.x && first.y === end.y && first.width === end.width && first.height === end.height) continue;
      root.animate(
        [{ transform: `translate(${first.x}px, ${first.y}px) scale(${first.width / end.width}, ${first.height / end.height})` },
          { transform: `translate(${end.x}px, ${end.y}px)` }],
        {
          pseudoElement: `::view-transition-group(${name})`,
          duration: name === "content-indicator" ? 180 : 320,
          easing: move,
        },
      );
    }
  }).catch(() => undefined);
  return transition.updateCallbackDone;
}
