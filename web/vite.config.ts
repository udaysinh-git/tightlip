import { fileURLToPath } from "node:url";
import solid from "@solidjs/vite-plugin";
import { defineConfig } from "vite";
import { devMock } from "./dev/vite-mock.ts";
import { delivery, solidRuntime, verifyTemplates } from "./scripts/delivery.ts";

export default defineConfig({
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
});
