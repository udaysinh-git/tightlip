import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Plugin, PreviewServer } from "vite";
import { shareId } from "../src/wire.ts";

const securityHeaders = {
  "Content-Security-Policy": "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types tightlip-templates tightlip-worker",
  "Integrity-Policy": "blocked-destinations=(script)",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

async function mock() {
  const { createMockServer } = await import("./mock-server.ts");
  return createMockServer(new URL("../pkg/mock/tightlip.js", import.meta.url));
}

function serveBuiltRoutes(server: PreviewServer) {
  server.middlewares.use((request, response, next) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    if (path === "/" || path === "/security" || shareId(path) !== undefined) {
      response.setHeader("Cache-Control", "no-cache");
      request.url = "/index.html";
      next();
      return;
    }
    if (path === "/.well-known/tightlip-release.json") {
      response.setHeader("Cache-Control", "no-cache");
      request.url = "/release.json";
      next();
      return;
    }
    if (path === "/robots.txt" || path === "/sitemap.xml" || path === "/og.png") {
      response.setHeader("Cache-Control", path === "/og.png" ? "public, max-age=86400" : "public, max-age=3600");
      next();
      return;
    }
    if (/^\/assets\/[A-Za-z0-9_.-]+$/.test(path)
      && existsSync(resolve(server.config.root, server.config.build.outDir, path.slice(1)))) {
      response.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      next();
      return;
    }
    response.writeHead(404).end();
  });
}

export function devMock(): Plugin {
  return {
    name: "tightlip-development-mock",
    apply: "serve",
    async configureServer(server) {
      if (process.env.VITEST) return;
      const { middleware, close } = await mock();
      server.httpServer?.once("close", close);
      server.middlewares.use(middleware);
    },
    async configurePreviewServer(server) {
      if (process.env.TIGHTLIP_TEST_PREVIEW !== "1") return;
      const { middleware, close } = await mock();
      server.httpServer.once("close", close);
      server.middlewares.use((_, response, next) => {
        for (const [name, value] of Object.entries(securityHeaders)) response.setHeader(name, value);
        next();
      });
      server.middlewares.use(middleware);
      serveBuiltRoutes(server);
    },
  };
}
