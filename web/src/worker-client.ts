import { workerScript } from "./trusted-types";
import type { Operation, Operations, Progress, Reply, Request, Result } from "./worker-protocol";

export class WorkerError extends Error {
  constructor(message: string, readonly usedView: boolean, readonly wrongPassword = false) {
    super(message);
  }
}

interface Pending {
  resolve: (result: Result) => void;
  reject: (error: Error) => void;
  progress?: (value: Progress) => void;
}

export class CryptoClient {
  #worker: Worker | undefined;
  #id = 0;
  #pending = new Map<number, Pending>();

  #start(): Worker {
    const worker = new Worker(workerScript(), { type: "module" });
    worker.onmessage = ({ data }: MessageEvent<Reply>) => {
      const pending = this.#pending.get(data.id);
      if (!pending) return;
      if ("progress" in data) {
        pending.progress?.(data.progress);
        return;
      }
      this.#pending.delete(data.id);
      if ("error" in data) pending.reject(new WorkerError(data.error, data.usedView, data.wrongPassword));
      else pending.resolve(data.result);
    };
    worker.onerror = worker.onmessageerror = () => this.close();
    return worker;
  }

  call<K extends Operation>(
    operation: K, input: Operations[K]["input"], progress?: (value: Progress) => void,
  ): Promise<Operations[K]["output"]> {
    return new Promise((resolve, reject) => {
      const worker = this.#worker ??= this.#start();
      const id = ++this.#id;
      this.#pending.set(id, { resolve: (value) => resolve(value as Operations[K]["output"]), reject, progress });
      const request = { id, operation, input } as Request;
      try {
        worker.postMessage(request);
      } catch (error) {
        this.#pending.delete(id);
        reject(error);
      }
    });
  }

  close() {
    this.#worker?.terminate();
    this.#worker = undefined;
    for (const { reject } of this.#pending.values()) {
      reject(new Error("The browser stopped the crypto worker. Reload this page and try again."));
    }
    this.#pending.clear();
  }
}
