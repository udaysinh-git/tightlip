// Adapted from Bencho "Toast stack" (bencho.dev), used under the Bencho Pro licence.
import { For, createSignal } from "solid-js";
import { IconButton } from "./ui";
import { isPointer, motionAllowed } from "./transitions";

interface Toast {
  id: number;
  message: string;
  error: boolean;
  animate: boolean;
}

export function createToasts() {
  const [entries, setEntries] = createSignal<Toast[]>([]);
  let nextId = 0;
  return {
    entries,
    notify(message: string, error = false, pointer = isPointer()) {
      if (!message) {
        setEntries((toasts) => toasts.filter((toast) => toast.error !== error));
        return;
      }
      const toast = { message, error, animate: motionAllowed(pointer), id: ++nextId };
      setEntries((toasts) => [toast, ...toasts.filter((item) => item.message !== message)].slice(0, 3));
    },
    dismiss(id: number) {
      setEntries((toasts) => toasts.filter((toast) => toast.id !== id));
    },
  };
}

export function ToastStack(props: { toasts: ReturnType<typeof createToasts> }) {
  const [open, setOpen] = createSignal(false);
  let region: HTMLElement | undefined;
  return (
    <section class="toast-stack" aria-label="Notifications" hidden={!props.toasts.entries().length}
      ref={(element) => { region = element; }} tabindex={-1} data-expanded={open() ? "" : undefined}>
      <For each={props.toasts.entries()}>{(toast, rank) => (
        <div class="toast" data-animate={toast.animate ? "" : undefined} data-rank={rank()}
          data-error={toast.error ? "" : undefined}>
          <p role={rank() === 0 ? toast.error ? "alert" : "status" : undefined}>{toast.message}</p>
          <IconButton icon="remove" label="Dismiss notification" onClick={(event) => {
            props.toasts.dismiss(toast.id);
            if (event.detail === 0 && props.toasts.entries().length) region?.focus();
          }} />
        </div>
      )}</For>
      <button class="visually-hidden toast-expander" type="button" aria-expanded={open() ? "true" : "false"}
        hidden={props.toasts.entries().length < 2} onClick={() => setOpen((value) => !value)}>
        {open() ? "Collapse notifications" : "Show all notifications"}
      </button>
    </section>
  );
}
