export default function init(options?: {
  module_or_path: Response | BufferSource | URL | string | WebAssembly.Module;
}): Promise<unknown>;

interface Handle {
  free(): void;
}

export class LinkSecret implements Handle {
  static generate(): LinkSecret;
  static parse(path: string, fragment: string): LinkSecret;
  format(authority: string, id: string): string;
  start(password?: string): Exchange;
  free(): void;
}

export class OwnerToken implements Handle {
  static generate(): OwnerToken;
  verifier(): string;
  bearer(): string;
  free(): void;
}

export interface Exchange extends Handle {
  blinded(): string;
  finish(evaluated: string, id: string): ShareSession;
}

export interface ShareSession extends Handle {
  access_tag(): string;
  access_verifier(): string;
  draft(content: string): Draft;
  seal_manifest(draft: Draft): Uint8Array<ArrayBuffer>;
  open_manifest(encoded: string, count: number): OpenedManifest;
  seal_file_init(draft: Draft, name: string, mime: string, size: number, orientation?: number): FileSeal;
}

export type Draft = Handle;

export interface FileSeal extends Handle {
  header(): Uint8Array<ArrayBuffer>;
  update(bytes: Uint8Array): Uint8Array<ArrayBuffer>;
  finish(): Uint8Array<ArrayBuffer>;
}

export interface FileOpen extends Handle {
  update(bytes: Uint8Array): Uint8Array<ArrayBuffer>;
  finish(): Uint8Array<ArrayBuffer>;
}

export interface OpenedManifest extends Handle {
  visible_content(): string;
  decrypt_file_init(index: number, header: Uint8Array): FileOpen;
}

export function file_header_length(): number;
export function generate_password(): string;
export function strip_image_metadata(bytes: Uint8Array, mime: string): Handle & {
  bytes(): Uint8Array<ArrayBuffer>;
  orientation(): number | undefined;
};
