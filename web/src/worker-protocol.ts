import type { Metadata } from "./api";

export const loginFields = {
  title: "Title",
  username: "Username",
  password: "Password",
  url: "URL",
  totp: "TOTP secret",
  note: "Note",
} as const;

export type LoginField = keyof typeof loginFields;
export type Login = Partial<Record<LoginField, string>>;

export interface Content {
  note?: string;
  login?: Login;
}

export interface VisibleFile {
  name: string;
  mime: string;
  size: number;
  orientation?: number;
}

export interface RevealedFile extends VisibleFile {
  blob: Blob;
}

export interface Revealed extends Content {
  files: RevealedFile[];
  failedFiles: string[];
  viewsLeft?: number;
}

export interface CreateInput {
  content: Content;
  files: File[];
  password?: string;
  ttl: number;
  views: number;
}

export interface Created {
  link: string;
  expiresAt: number;
}

export interface Progress {
  phase: "encrypting" | "uploading";
  current: number;
  total: number;
  loaded: number;
  size: number;
}

export interface Operations {
  create: { input: CreateInput; output: Created };
  remove: { input: undefined; output: boolean };
  password: { input: undefined; output: string };
  load: { input: { path: string; fragment: string }; output: Metadata };
  reveal: { input: { password?: string }; output: Revealed };
}

export type Operation = keyof Operations;
export type Request = {
  [K in Operation]: { id: number; operation: K; input: Operations[K]["input"] }
}[Operation];
export type Result = Operations[Operation]["output"];
export type Reply =
  | { id: number; progress: Progress }
  | { id: number; result: Result }
  | { id: number; error: string; usedView: boolean; attemptsLeft?: number };
