// Adapted from Bencho "Nib", "Check", and "Toss" (bencho.dev), used under the Bencho Pro licence.
interface Note {
  hz: number;
  to?: number;
  ms: number;
  gain: number;
  wave?: OscillatorType;
  cut?: number;
  atk: number;
  noise?: BiquadFilterType;
  q?: number;
  lin?: boolean;
}

const notes = {
  tap: [
    { hz: 1900, ms: 12, gain: 0.058, noise: "bandpass", q: 2.5, atk: 1 },
    { hz: 2250, to: 2000, ms: 12, gain: 0.046, atk: 1 },
    { hz: 300, ms: 10, gain: 0.023, atk: 1 },
  ],
  copied: [{ hz: 370, ms: 90, gain: 0.055, wave: "square", cut: 2400, atk: 10 }],
  dissolve: [{ hz: 1100, to: 520, ms: 170, gain: 0.03, q: 0.8, noise: "bandpass", atk: 40, lin: true }],
} satisfies Record<string, Note[]>;

const preference = "tightlip:sounds";
let enabled = false;
try { enabled = localStorage.getItem(preference) === "on"; } catch { /* Storage can be disabled. */ }
let context: AudioContext | undefined;
let noise: AudioBuffer | undefined;

export function soundsEnabled() {
  return enabled;
}

export function setSounds(value: boolean) {
  enabled = value;
  try { localStorage.setItem(preference, value ? "on" : "off"); } catch { /* Keep the session preference. */ }
  if (!value) {
    void context?.close().catch(() => undefined);
    context = undefined;
    noise = undefined;
  }
}

export function prepareSound() {
  if (!enabled || typeof AudioContext !== "function") return;
  try {
    context ??= new AudioContext();
    if (context.state === "suspended") void context.resume().catch(() => undefined);
  } catch { /* Audio feedback is optional. */ }
}

function schedule(ctx: AudioContext, note: Note, start: number) {
  const end = start + note.ms / 1000;
  let source: AudioScheduledSourceNode;
  let head: AudioNode;
  if (note.noise) {
    if (!noise) {
      noise = ctx.createBuffer(1, ctx.sampleRate * 2, ctx.sampleRate);
      const samples = noise.getChannelData(0);
      for (let i = 0; i < samples.length; i += 1) samples[i] = Math.random() * 2 - 1;
    }
    const buffer = ctx.createBufferSource();
    buffer.buffer = noise;
    buffer.loop = true;
    const filter = ctx.createBiquadFilter();
    filter.type = note.noise;
    filter.Q.value = note.q ?? 1;
    filter.frequency.setValueAtTime(note.hz, start);
    if (note.to) filter.frequency.exponentialRampToValueAtTime(note.to, end);
    buffer.connect(filter);
    source = buffer;
    head = filter;
  } else {
    const oscillator = ctx.createOscillator();
    oscillator.type = note.wave ?? "sine";
    oscillator.frequency.setValueAtTime(note.hz, start);
    if (note.to) oscillator.frequency.exponentialRampToValueAtTime(note.to, end);
    source = oscillator;
    head = oscillator;
  }
  if (note.cut) {
    const filter = ctx.createBiquadFilter();
    filter.frequency.value = note.cut;
    head.connect(filter);
    head = filter;
  }
  const gain = ctx.createGain();
  const attack = start + Math.min(note.atk, note.ms * 0.6) / 1000;
  gain.gain.setValueAtTime(0.0001, start);
  if (note.lin) gain.gain.linearRampToValueAtTime(note.gain * 0.5, attack);
  else gain.gain.exponentialRampToValueAtTime(note.gain * 0.5, attack);
  gain.gain.exponentialRampToValueAtTime(0.0001, end);
  head.connect(gain).connect(ctx.destination);
  if (source instanceof AudioBufferSourceNode) source.start(start, Math.random() * 1.5);
  else source.start(start);
  source.stop(end + 0.02);
}

export function playSound(cue: keyof typeof notes) {
  if (!enabled) return;
  prepareSound();
  const ctx = context;
  if (!ctx) return;
  try {
    const start = ctx.currentTime + 0.005;
    for (const note of notes[cue]) schedule(ctx, note, start);
  } catch { /* Audio feedback is optional. */ }
}
