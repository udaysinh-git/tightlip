import { setTrustedTypesPolicy, template as solidTemplate } from "@solidjs/web";
import workerUrl from "./crypto-worker?worker&url";

interface Policy {
  createHTML(value: string): unknown;
  createScriptURL(value: string): unknown;
}

const trustedTypes = (globalThis as typeof globalThis & {
  trustedTypes?: {
    createPolicy(name: string, rules: Partial<Record<keyof Policy, (value: string) => string>>): Policy;
  };
}).trustedTypes;

const templates = new Set<string>();

// Only the Solid JSX compiler imports this wrapper. Its build checks require literal templates.
export function template(html: string, flag?: 1 | 2) {
  templates.add(html);
  return solidTemplate(html, flag);
}

if (trustedTypes) {
  const policy = trustedTypes.createPolicy("tightlip-templates", {
    createHTML(value) {
      if (!templates.has(value)) throw new TypeError("Unrecognized Solid template");
      return value;
    },
  });
  setTrustedTypesPolicy(policy);
}

let trustedWorkerUrl: string | undefined;

export function workerScript(): string {
  if (trustedWorkerUrl) return trustedWorkerUrl;
  const normalized = new URL(workerUrl, location.href);
  if (normalized.origin !== location.origin) throw new TypeError("Unexpected worker origin");
  const source = normalized.href;
  const policy = trustedTypes?.createPolicy("tightlip-worker", {
    createScriptURL(value) {
      if (value !== source) throw new TypeError("Unrecognized worker URL");
      return value;
    },
  });
  trustedWorkerUrl = policy ? policy.createScriptURL(source) as string : source;
  return trustedWorkerUrl;
}
