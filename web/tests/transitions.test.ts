import { afterEach, describe, expect, it, vi } from "vitest";
import { changeView, finishViewTransition } from "../src/transitions";

afterEach(() => {
  finishViewTransition();
  vi.unstubAllGlobals();
});

describe("View Transitions", () => {
  it("applies the update synchronously when startViewTransition is missing", async () => {
    vi.stubGlobal("document", { startViewTransition: undefined });
    const update = vi.fn();
    const done = changeView("link", update, true);
    expect(update).toHaveBeenCalledTimes(1);
    await done;
    expect(update).toHaveBeenCalledTimes(1);
  });

  it("skips the browser transition for keyboard and reduced motion", async () => {
    const startViewTransition = vi.fn();
    vi.stubGlobal("document", { startViewTransition });
    vi.stubGlobal("window", { matchMedia: () => ({ matches: true }) });
    const update = vi.fn();
    await changeView("reveal", update, true);
    vi.stubGlobal("window", { matchMedia: () => ({ matches: false }) });
    await changeView("reveal", update, false);
    expect(update).toHaveBeenCalledTimes(2);
    expect(startViewTransition).not.toHaveBeenCalled();
  });

  it("runs Solid updates inside the callback and skips a prior animation on retargeting", async () => {
    const callbacks: (() => void)[] = [];
    const skips: ReturnType<typeof vi.fn>[] = [];
    const startViewTransition = vi.fn((callback: () => void) => {
      let resolveUpdate: (() => void) | undefined;
      const updateCallbackDone = new Promise<void>((resolve) => { resolveUpdate = resolve; });
      callbacks.push(() => { callback(); resolveUpdate?.(); });
      const skipTransition = vi.fn();
      skips.push(skipTransition);
      return { ready: new Promise(() => undefined), finished: new Promise(() => undefined),
        updateCallbackDone, skipTransition };
    });
    vi.stubGlobal("document", {
      startViewTransition, documentElement: { dataset: {} }, querySelectorAll: () => [],
    });
    vi.stubGlobal("window", { matchMedia: () => ({ matches: false }) });
    const updates: string[] = [];
    const first = changeView("forward", () => { updates.push("first"); }, true);
    expect(updates).toEqual([]);
    const next = changeView("back", () => { updates.push("next"); }, true);
    expect(skips[0]).toHaveBeenCalledOnce();
    expect(updates).toEqual([]);
    callbacks[1]?.();
    callbacks[0]?.();
    await Promise.all([first, next]);
    expect(updates).toEqual(["first", "next"]);
  });
});
