import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const target = resolve(root, "web/pkg/target");
const executable = process.platform === "win32" ? "wasm-bindgen.exe" : "wasm-bindgen";
const bindgen = process.env.WASM_BINDGEN || executable;

function run(command, args, overrides = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: { ...process.env, CARGO_BUILD_JOBS: "2", ...overrides },
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with status ${result.status}`);
}

export function buildWasm(mode) {
  const cli = bindgen.includes("/") || bindgen.includes("\\")
    ? isAbsolute(bindgen) ? bindgen : resolve(process.cwd(), bindgen)
    : bindgen;
  const output = resolve(root, "web/pkg", mode);
  mkdirSync(output, { recursive: true });
  const cargoRegistry = resolve(process.env.CARGO_HOME || resolve(homedir(), ".cargo"), "registry/src");
  const flags = process.env.CARGO_ENCODED_RUSTFLAGS?.split("\x1f")
    ?? process.env.RUSTFLAGS?.trim().split(/\s+/)
    ?? [];
  const remapped = [
    ...flags.filter(Boolean),
    `--remap-path-prefix=${resolve(root)}=.`,
    `--remap-path-prefix=${cargoRegistry}=/cargo-registry`,
  ];
  run("cargo", [
    "build", "--locked", "-p", "tightlip-wasm", "--release",
    "--target", "wasm32-unknown-unknown", "--target-dir", target,
    ...(mode === "mock" ? ["--features", "dev-mock"] : []),
  ], { CARGO_ENCODED_RUSTFLAGS: remapped.join("\x1f") });
  run(cli, [
    "--target", "web", "--out-dir", output, "--out-name", "tightlip",
    resolve(target, "wasm32-unknown-unknown/release/tightlip_wasm.wasm"),
  ]);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildWasm("client");
}
