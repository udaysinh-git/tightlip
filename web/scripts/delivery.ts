import { createHash } from "node:crypto";
import type { Plugin } from "vite";

function sha384(value: string | Uint8Array): string {
  return `sha384-${createHash("sha384").update(value).digest("base64")}`;
}

export function delivery(): Plugin {
  return {
    name: "tightlip-static-delivery",
    apply: "build",
    generateBundle: {
      order: "post",
      handler(_, bundle) {
        const index = bundle["index.html"];
        // The worker build has no HTML entry.
        if (!index || index.type !== "asset" || typeof index.source !== "string") return;
        const hashes: Record<string, string> = {};
        for (const name of Object.keys(bundle).sort()) {
          const file = bundle[name];
          if (name.startsWith("assets/") && file) {
            hashes[name] = sha384(file.type === "asset" ? file.source : file.code);
          }
        }
        let scripts = 0;
        let styles = 0;
        index.source = index.source.replace(/<(script|link)\b([^>]*?)>/g, (_, tag: string, attrs: string) => {
          if (tag === "script" && /\btype="application\/ld\+json"/.test(attrs)) return `<${tag}${attrs}>`;
          if (tag === "link" && !/\brel="(?:stylesheet|modulepreload)"/.test(attrs)) return `<${tag}${attrs}>`;
          const url = /\b(?:src|href)="\/([^"]+)"/.exec(attrs)?.[1];
          const integrity = url && hashes[url];
          if (!integrity) this.error("Each built script and style must be a hashed local asset.");
          if (tag === "script") scripts += 1;
          else styles += 1;
          return `<${tag}${attrs} integrity="${integrity}">`;
        });
        if (scripts !== 1 || styles !== 1 || /<style\b/.test(index.source)) {
          this.error("Expected one external entry script and one external stylesheet.");
        }
        const entries = Object.values(bundle).filter((file) => file.type === "chunk");
        if (entries.length !== 1 || entries.some((file) => file.imports.length || file.dynamicImports.length)) {
          this.error("The page script must be a single self-contained module with integrity metadata.");
        }
      },
    },
  };
}

type Syntax = Record<string, unknown>;

function node(value: unknown): value is Syntax {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function walk(value: unknown, visit: (value: Syntax) => void) {
  if (Array.isArray(value)) {
    value.forEach((child: unknown) => walk(child, visit));
  } else if (node(value)) {
    if (typeof value.type === "string") visit(value);
    for (const child of Object.values(value)) walk(child, visit);
  }
}

export const solidRuntime = "tightlip-solid-dom";

export function verifyTemplates(): Plugin {
  return {
    name: "tightlip-verify-solid-templates",
    apply: "build",
    enforce: "post",
    transform(code, id) {
      if (!id.endsWith(".tsx") || !code.includes(solidRuntime)) return;
      const program = this.parse(code);
      const bindings = new Set<string>();
      walk(program, (value) => {
        if (value.type !== "ImportDeclaration" || !node(value.source) || value.source.value !== solidRuntime
          || !Array.isArray(value.specifiers)) return;
        for (const specifier of value.specifiers as unknown[]) {
          if (node(specifier) && node(specifier.imported) && specifier.imported.name === "template"
            && node(specifier.local) && typeof specifier.local.name === "string") {
            bindings.add(specifier.local.name);
          }
        }
      });
      walk(program, (value) => {
        if (value.type !== "CallExpression" || !node(value.callee) || typeof value.callee.name !== "string"
          || !bindings.has(value.callee.name)) return;
        const arg: unknown = Array.isArray(value.arguments) ? value.arguments[0] : undefined;
        if (node(arg) && ((arg.type === "Literal" && typeof arg.value === "string")
          || (arg.type === "TemplateLiteral" && Array.isArray(arg.expressions) && !arg.expressions.length))) return;
        this.error("Solid HTML templates must be compile-time string literals.");
      });
    },
  };
}
