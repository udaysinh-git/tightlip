// Adapted from Bencho "Rolling counter" (bencho.dev), used under the Bencho Pro licence.
export function RollingCounter(props: { count: number; previous: number; animate: boolean }) {
  return (
    <span class="counter" data-roll={props.animate && props.previous !== props.count ? "" : undefined}>
      <span class="counter-value">{props.count}</span>
      <span class="counter-window" aria-hidden="true">
        <span class="counter-strip"><span>{props.previous}</span><span>{props.count}</span></span>
      </span>
    </span>
  );
}
