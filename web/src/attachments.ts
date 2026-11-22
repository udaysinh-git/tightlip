import { rasterType } from "./image-types";
import type { RevealedFile, VisibleFile } from "./worker-protocol";

export function safeFileName(name: string): string {
  return name.replace(/[\x00-\x1f\u202a-\u202e\u2066-\u2069]/g, "") || "attachment";
}

export function fileNameParts(name: string): [string, string] {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
}

export async function revealAttachment(entry: VisibleFile, parts: Blob[]): Promise<RevealedFile> {
  const download = new Blob(parts, { type: "application/octet-stream" });
  const type = rasterType(new Uint8Array(await download.slice(0, 12).arrayBuffer()));
  return {
    name: safeFileName(entry.name),
    size: entry.size,
    orientation: type === "image/jpeg" ? entry.orientation : undefined,
    download,
    preview: type ? new Blob([download], { type }) : undefined,
  };
}
