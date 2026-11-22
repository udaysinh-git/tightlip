import { createSignal, Show } from "solid-js";

export function createFeedback() {
  const [error, setError] = createSignal("");
  const [status, setStatus] = createSignal("");
  return {
    error, status, setError,
    notify(value: string, failed = false) {
      setError(failed ? value : "");
      setStatus(failed ? "" : value);
    },
  };
}

export function Feedback(props: { feedback: ReturnType<typeof createFeedback> }) {
  return (
    <>
      <Show when={props.feedback.error()}>
        <p class="inline-error" role="alert">{props.feedback.error()}</p>
      </Show>
      <p class="inline-status" role="status">{props.feedback.status()}</p>
    </>
  );
}
