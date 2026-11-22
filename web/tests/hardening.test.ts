import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { fileNameParts, revealAttachment, safeFileName } from "../src/attachments";
import { rasterType } from "../src/image-types";

async function tsxFiles(dir: string): Promise<string[]> {
  const excluded = new Set(["node_modules", "pkg", "dist", "test-results"]);
  const files = await Promise.all((await readdir(dir, { withFileTypes: true })).map(async (entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory() && !excluded.has(entry.name)) return tsxFiles(path);
    return entry.isFile() && entry.name.endsWith(".tsx") ? [path] : [];
  }));
  return files.flat();
}

it("passes spellcheck as a string throughout the TSX source", async () => {
  const files = await tsxFiles(fileURLToPath(new URL("../", import.meta.url)));
  expect(files.length).toBeGreaterThan(0);
  const offenders = await Promise.all(files.map(async (file) => {
    const source = await readFile(file, "utf8");
    return /\bspellcheck\s*=\s*\{\s*false\s*\}/.test(source) ? file : undefined;
  }));
  expect(offenders.filter(Boolean)).toEqual([]);
});

it.each([
  ["image/svg+xml", "<svg><script>synthetic example</script></svg>"],
  ["text/html", "<!doctype html><p>synthetic example</p>"],
])("keeps attachments with manifest type %s out of previews", async (mime, bytes) => {
  const name = "invoice\u202efdp\u2066.\u0000exe\u2069";
  const file = await revealAttachment({ name, mime, size: bytes.length }, [new Blob([bytes])]);
  expect(file.preview).toBeUndefined();
  expect(file.download.type).toBe("application/octet-stream");
  expect(await file.download.text()).toBe(bytes);
  expect(file.name).toBe("invoicefdp.exe");
  expect(fileNameParts(file.name)).toEqual(["invoicefdp", ".exe"]);
  expect(safeFileName("\u001f\u202a")).toBe("attachment");
});

it("makes a distinct raster preview and octet-stream download", async () => {
  const image = new Blob(["GIF89a"]);
  const file = await revealAttachment({ name: "pixel.gif", mime: "text/html", size: image.size }, [image]);
  expect(file.download.type).toBe("application/octet-stream");
  expect(file.preview?.type).toBe("image/gif");
  expect(await file.preview?.text()).toBe(await file.download.text());
});

it.each([
  [[0xff, 0xd8, 0xff], "image/jpeg"],
  [[137, 80, 78, 71, 13, 10, 26, 10], "image/png"],
  [[82, 73, 70, 70, 0, 0, 0, 0, 87, 69, 66, 80], "image/webp"],
  [[66, 77], undefined],
  [[0, 0, 1, 0], undefined],
])("identifies supported raster formats from their leading bytes", (bytes, expected) => {
  expect(rasterType(new Uint8Array(bytes))).toBe(expected);
});
