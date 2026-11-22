const jpeg = [0xff, 0xd8, 0xff];
const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

function startsWith(bytes: Uint8Array, signature: string, offset = 0): boolean {
  return Array.from(signature).every((character, i) => bytes[offset + i] === character.charCodeAt(0));
}

export function rasterType(head: Uint8Array): string | undefined {
  if (jpeg.every((byte, i) => head[i] === byte)) return "image/jpeg";
  if (png.every((byte, i) => head[i] === byte)) return "image/png";
  if (startsWith(head, "GIF87a") || startsWith(head, "GIF89a")) return "image/gif";
  if (startsWith(head, "RIFF") && startsWith(head, "WEBP", 8)) return "image/webp";
  return undefined;
}

export function scrubType(head: Uint8Array): string | undefined {
  const type = rasterType(head);
  return type === "image/gif" ? undefined : type;
}
