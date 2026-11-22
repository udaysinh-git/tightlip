// Adapted from Bencho "Rolling counter" (bencho.dev), used under the Bencho Pro licence.
import { For, createRenderEffect } from "solid-js";

const glyphs = Array.from({ length: 30 }, (_, index) => index);

function Digit(props: { count: number; place: number }) {
  const number = () => Math.floor(props.count / 10 ** props.place);
  let previous = number();
  let strip: HTMLSpanElement | undefined;
  const position = (value: number) => strip?.style.setProperty("--digit-offset", `${-value}em`);
  createRenderEffect(number, (value) => {
    if (value === previous) return;
    // The duplicated strip crosses 0 without running backwards on a borrow.
    const before = previous % 10;
    const after = ((before + (value - previous)) % 10 + 10) % 10;
    const start = before + 10;
    const distance = Math.min(10, Math.abs(value - previous)) * Math.sign(value - previous);
    if (strip) {
      strip.dataset.reset = "";
      position(start);
      void strip.offsetWidth;
      delete strip.dataset.reset;
      position(Math.abs(value - previous) > 10 ? after + 10 : start + distance);
    }
    previous = value;
  });
  return (
    <span class="counter-window" hidden={props.place > 0 && props.count < 10 ** props.place}>
      <span class="counter-strip" ref={(element) => {
        strip = element;
        element.style.setProperty("--digit-delay", `${props.place * 45}ms`);
        position(10 + number() % 10);
      }}>
        <For each={glyphs}>{(number) => <span>{number % 10}</span>}</For>
      </span>
    </span>
  );
}

export function RollingCounter(props: { count: number; animate?: boolean }) {
  const digits = String(props.count).length;
  const places = Array.from({ length: digits }, (_, index) => digits - 1 - index);
  return (
    <span class="views-left" aria-label={`${props.count} ${props.count === 1 ? "view" : "views"} left.`}>
      <span class="counter" data-animate={props.animate ? "" : undefined} aria-hidden="true">
        <For each={places}>{(place) => <Digit count={props.count} place={place} />}</For>
      </span>
      <span class="visually-hidden">{props.count} </span>
      <span> {props.count === 1 ? "view" : "views"} left.</span>
    </span>
  );
}
