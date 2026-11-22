const jpeg = [0xff, 0xd8];
const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const previews = new Set(["image/jpeg", "image/png", "image/gif", "image/webp", "image/avif",
  "image/bmp", "image/x-icon", "image/vnd.microsoft.icon", "image/svg+xml"]);

export function supportedImage(mime: string): boolean {
  return previews.has(mime);
}

export function scrubType(mime: string, head: Uint8Array): string | undefined {
  if (jpeg.every((byte, i) => head[i] === byte)) return "image/jpeg";
  if (png.every((byte, i) => head[i] === byte)) return "image/png";
  if (mime === "image/jpeg" || mime === "image/png") return mime;
  return undefined;
}
