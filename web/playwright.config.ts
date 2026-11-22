import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  workers: 1,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  use: { ...devices["Desktop Chrome"], baseURL: "http://127.0.0.1:4187" },
  webServer: {
    command: "npm exec -- vite preview --host 127.0.0.1 --port 4187 --strictPort",
    env: { TIGHTLIP_TEST_PREVIEW: "1" },
    url: "http://127.0.0.1:4187/healthz",
    reuseExistingServer: false,
  },
});
