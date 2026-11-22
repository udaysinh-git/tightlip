// Adapted from Bencho "Dust delete" (bencho.dev), used under the Bencho Pro licence.
import { motionAllowed } from "./transitions";

const duration = 400;
const release = 145;

export function scatterDust(box: DOMRect, began: number): () => void {
  if (performance.now() - began >= duration || !motionAllowed()) return () => undefined;
  const width = window.innerWidth;
  const height = window.innerHeight;
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  canvas.className = "dust-canvas";
  canvas.setAttribute("aria-hidden", "true");
  const ctx = canvas.getContext("2d");
  if (!ctx) return () => undefined;

  // Sample visible panel geometry, without copying secret text or image pixels to a canvas.
  const grains: { x: number; y: number; at: number; dx: number; dy: number; size: number }[] = [];
  const left = Math.max(box.left, 0);
  const right = Math.min(box.right, width);
  const top = Math.max(box.top, 0);
  const bottom = Math.min(box.bottom, height);
  const grain = Math.max(7, Math.sqrt(Math.max(0, right - left) * Math.max(0, bottom - top) / 220));
  for (let y = top; y < bottom; y += grain) {
    for (let x = left; x < right; x += grain) {
      grains.push({
        x, y, at: (right - x) / (right - left) * release + Math.random() * 20,
        dx: 12 + Math.random() * 34, dy: -5 - Math.random() * 16, size: 1 + Math.random() * 2,
      });
    }
  }
  if (!grains.length) return () => undefined;
  document.body.append(canvas);
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--secondary");
  let frame = requestAnimationFrame(draw);

  function stop() {
    cancelAnimationFrame(frame);
    canvas.remove();
  }

  function draw(now: number) {
    const elapsed = now - began;
    if (elapsed >= duration || !motionAllowed() || document.visibilityState === "hidden" || !ctx) {
      stop();
      return;
    }
    ctx.clearRect(0, 0, width, height);
    for (const grain of grains) {
      if (elapsed < grain.at) continue;
      const age = (elapsed - grain.at) / (duration - grain.at);
      const drift = 1 - (1 - age) ** 2;
      ctx.globalAlpha = 0.62 * (1 - age * age) * Math.min(1, age * 12);
      ctx.fillRect(grain.x + grain.dx * drift, grain.y + grain.dy * drift, grain.size, grain.size);
    }
    frame = requestAnimationFrame(draw);
  }

  return stop;
}
