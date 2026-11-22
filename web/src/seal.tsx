import { Icon } from "./icons";

export function Seal(props: { capture?: (element: HTMLSpanElement) => void }) {
  return (
    <span class="wax-seal" aria-hidden="true" ref={props.capture}>
      <span class="wax-half wax-left"><Icon name="lock" /></span>
      <span class="wax-half wax-right"><Icon name="lock" /></span>
    </span>
  );
}

export function SealGlyph() {
  return <span class="seal-glyph"><Icon name="lock" /></span>;
}
