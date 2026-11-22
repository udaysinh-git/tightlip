import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, open, readFile, readdir, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("../", import.meta.url));
const dist = join(web, "dist");
const supplied = process.env.TIGHTLIP_RELEASE_COMMIT;
async function gitMetadata() {
  const directory = await mkdtemp(join(tmpdir(), "tightlip-release-"));
  const output = join(directory, "metadata");
  async function git(...args) {
    const file = await open(output, "w");
    try {
      execFileSync("git", ["--no-optional-locks", ...args], { cwd: web, stdio: ["ignore", file.fd, "inherit"] });
    } finally {
      await file.close();
    }
    return (await readFile(output, "utf8")).trim();
  }
  try {
    return { commit: await git("rev-parse", "HEAD"), dirty: Boolean(await git("status", "--porcelain")) };
  } finally {
    await unlink(output).catch((error) => { if (error.code !== "ENOENT") throw error; });
    await rmdir(directory);
  }
}

// Docker builds without a commit argument (the hosting panel passes none) still publish file hashes;
// the commit is then recorded as "unknown" and the manifest cannot be tied to a tag.
const { commit, dirty } = supplied === undefined ? await gitMetadata().catch(() => ({ commit: "unknown", dirty: false }))
  : supplied === "" ? { commit: "unknown", dirty: false } : { commit: supplied, dirty: false };
if (commit !== "unknown" && !/^[0-9a-f]{40}$/.test(commit)) throw new Error("TIGHTLIP_RELEASE_COMMIT must be a full 40 character commit SHA.");
if (commit === "unknown") console.warn("release.json: no commit given, recording \"unknown\".");
const files = {};
const paths = (await readdir(dist, { recursive: true, withFileTypes: true }))
  .filter((entry) => entry.isFile())
  .map((entry) => join(entry.parentPath, entry.name).slice(dist.length + 1).replaceAll("\\", "/"))
  .filter((path) => path !== "release.json")
  .sort();
for (const path of paths) {
  files[path] = createHash("sha256").update(await readFile(join(dist, path))).digest("hex");
}
if (!files["index.html"]) throw new Error("The release needs dist/index.html.");
// The manifest cannot contain its own hash.
await writeFile(join(dist, "release.json"), `${JSON.stringify({ commit, dirty, files }, null, 2)}\n`);
