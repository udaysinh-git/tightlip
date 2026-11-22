import { Icon } from "./icons";
import type { JSX } from "@solidjs/web";

type IconName = Parameters<typeof Icon>[0]["name"];

export function IconButton(props: {
  icon: IconName;
  label: string;
  onClick: (event: MouseEvent) => void;
  disabled?: boolean;
  pressed?: boolean;
  expanded?: boolean;
  controls?: string;
  children?: JSX.Element;
}) {
  return (
    <button class="icon-button" type="button" title={props.label} aria-label={props.label}
      aria-pressed={ariaBoolean(props.pressed)} aria-expanded={ariaBoolean(props.expanded)}
      aria-controls={props.controls}
      disabled={props.disabled} onClick={(event) => props.onClick(event)}>
      <Icon name={props.icon} />
      {props.children}
    </button>
  );
}

function ariaBoolean(value: boolean | undefined) {
  return value === undefined ? undefined : value ? "true" : "false";
}

export function message(error: unknown) {
  return error instanceof Error ? error.message : "The action failed. Try again.";
}

export function Expiry(props: { seconds: number; label?: string }) {
  const date = () => new Date(props.seconds * 1000);
  const format = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  return <time datetime={date().toISOString()} title={format.format(date())}>
    {props.label ?? `Expires ${format.format(date())}`}
  </time>;
}

export function fileSize(size: number): string {
  if (size < 1000) return `${size} ${size === 1 ? "byte" : "bytes"}`;
  const format = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
  return size < 1_000_000 ? `${format.format(size / 1000)} kB` : `${format.format(size / 1_000_000)} MB`;
}
