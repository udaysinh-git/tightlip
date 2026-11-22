import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import solid from "@solidjs/vite-plugin";
import { defineConfig } from "vite";
import { devMock } from "./dev/vite-mock.ts";
import { delivery, solidRuntime, verifyTemplates } from "./scripts/delivery.ts";

export default defineConfig(({ command }) => ({
  define: {
    __TIGHTLIP_WASM_INTEGRITY__: JSON.stringify(command === "build"
      ? `sha384-${createHash("sha384").update(readFileSync(new URL("./pkg/client/tightlip_bg.wasm", import.meta.url))).digest("base64")}`
      : ""),
  },
  plugins: [solid({ solid: { moduleName: solidRuntime } }), verifyTemplates(), delivery(), devMock()],
  resolve: {
    alias: {
      "tightlip-wasm/client": fileURLToPath(new URL("./pkg/client/tightlip.js", import.meta.url)),
      [solidRuntime]: fileURLToPath(new URL("./src/solid-dom.ts", import.meta.url)),
    },
  },
  worker: { format: "es" },
  build: {
    assetsInlineLimit: 0,
    modulePreload: false,
    cssCodeSplit: false,
    rolldownOptions: { output: { comments: { legal: true } } },
  },
}));
