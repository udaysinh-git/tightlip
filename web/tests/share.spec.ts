import { deflateSync } from "node:zlib";
import { test, expect } from "@playwright/test";
import type { BrowserContext, Page } from "@playwright/test";

function pngChunk(type: string, body: Buffer) {
  const chunk = Buffer.alloc(body.length + 12);
  chunk.writeUInt32BE(body.length);
  chunk.write(type, 4);
  body.copy(chunk, 8);
  let crc = 0xffffffff;
  for (const byte of chunk.subarray(4, -4)) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  chunk.writeUInt32BE((~crc) >>> 0, chunk.length - 4);
  return chunk;
}

function png() {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const header = pngChunk("IHDR", Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
  const text = pngChunk("tEXt", Buffer.from("Comment\0Synthetic metadata"));
  const pixels = pngChunk("IDAT", deflateSync(Buffer.from([0, 128])));
  const end = pngChunk("IEND", Buffer.alloc(0));
  return { original: Buffer.concat([signature, header, text, pixels, end]),
    stripped: Buffer.concat([signature, header, pixels, end]) };
}

async function monitor(context: BrowserContext) {
  const violations: string[] = [];
  context.on("console", (entry) => {
    if (/content security policy|trustedhtml|trustedscripturl/i.test(entry.text())) violations.push(entry.text());
  });
  context.on("weberror", (event) => violations.push(event.error().message));
  await context.exposeBinding("reportCsp", (_, directive: string) => violations.push(directive));
  await context.addInitScript(() => {
    const app = window as Window & { reportCsp?: (directive: string) => void };
    document.addEventListener("securitypolicyviolation", (event) => app.reportCsp?.(event.violatedDirective));
  });
  return violations;
}

async function createLink(page: Page) {
  await page.getByRole("button", { name: "Create link" }).click();
  await expect(page.getByRole("heading", { name: "Link ready" })).toBeVisible();
  const link = new URL(await page.getByRole("textbox", { name: "Share link" }).inputValue());
  expect(link.protocol).toBe("https:");
  expect(link.pathname).toMatch(/^\/s\/[A-Za-z0-9_-]{22}$/);
  expect(link.hash).toMatch(/^#[A-Za-z0-9_-]{43}$/);
  // The test preview serves production assets on loopback HTTP.
  link.protocol = "http:";
  return link;
}

async function openLink(recipient: Page, link: URL) {
  const stateChanges: string[] = [];
  const track = (request: { method(): string; url(): string }) => {
    if (request.method() !== "GET" && request.url().includes("/api/v1/")) stateChanges.push(request.url());
  };
  recipient.context().on("request", track);
  try {
    const response = await recipient.goto(link.href);
    expect(response?.headers()["content-security-policy"]).toContain("require-trusted-types-for 'script'");
    await expect(recipient.getByRole("button", { name: "Reveal" })).toBeVisible();
    expect(recipient.url()).toBe(`${link.origin}${link.pathname}`);
    expect(stateChanges).toEqual([]);
  } finally {
    recipient.context().off("request", track);
  }
}

test("text renders as text after a click and the final view burns the share", async ({ page, browser }) => {
  const violations = await monitor(page.context());
  await page.goto("/");
  await expect(page.getByLabel("Expiry")).toHaveValue("86400");
  await expect(page.getByLabel("Views")).toHaveValue("1");
  await expect(page.locator("script[src][integrity]")).toHaveCount(1);
  await expect(page.locator("link[rel=stylesheet][integrity]")).toHaveCount(1);
  const text = "<img src=x onerror=alert(1)>\nSecond line.";
  await page.getByRole("textbox", { name: "Text" }).fill(text);
  const link = await createLink(page);
  const context = await browser.newContext();
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await expect(recipient.locator(".views-left")).toHaveAttribute("aria-label", "1 view left.");
    await expect(recipient.locator("pre")).toHaveCount(0);
    await recipient.getByRole("button", { name: "Reveal" }).click();
    await expect(recipient.locator("pre")).toHaveText(text);
    await expect(recipient.getByText("This was the last view.")).toBeVisible();
    await recipient.getByRole("button", { name: "Close share" }).click();
    await expect(recipient.getByRole("status")).toHaveText("This share is gone.");
    await expect(recipient.locator("pre")).toHaveCount(0);
    await recipient.goto(link.href);
    await expect(recipient.getByRole("alert")).toHaveText("This share is unavailable. Ask the sender for a new link.");
    expect([...violations, ...recipientViolations]).toEqual([]);
  } finally {
    await context.close();
  }
});

test("protected login accepts a correct password and allows the owner to delete it", async ({ page, browser }) => {
  const violations = await monitor(page.context());
  await page.goto("/");
  await page.getByRole("tab", { name: "Login" }).click();
  await page.getByLabel("Username", { exact: true }).fill("operator");
  await page.getByRole("button", { name: "Generate password" }).click();
  await expect(page.getByLabel("Password", { exact: true })).toHaveValue(/^[A-Za-z0-9_-]{43}$/);
  const loginPassword = await page.getByLabel("Password", { exact: true }).inputValue();
  await page.getByLabel("Views").selectOption("3");
  await page.getByRole("button", { name: "Share password" }).click();
  const sharePassword = "Synthetic share password";
  await page.getByLabel("Share password", { exact: true }).fill(sharePassword);
  const link = await createLink(page);
  const context = await browser.newContext();
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await expect(recipient.locator(".views-left")).toHaveAttribute("aria-label", "3 views left.");
    await recipient.getByLabel("Share password").fill("Wrong password");
    await recipient.getByRole("button", { name: "Reveal" }).click();
    await expect(recipient.getByRole("alert")).toContainText("Check the password");
    const metadata = await context.request.get(`${link.origin}/api/v1/shares/${link.pathname.slice(3)}`);
    expect((await metadata.json()).views_left).toBe(3);
    await recipient.getByLabel("Share password").fill(sharePassword);
    await recipient.getByRole("button", { name: "Reveal" }).click();
    await expect(recipient.getByText("operator", { exact: true })).toBeVisible();
    await expect(recipient.getByText(loginPassword, { exact: true })).toHaveCount(0);
    await recipient.getByRole("button", { name: "Show password" }).click();
    await expect(recipient.getByText(loginPassword, { exact: true })).toBeVisible();
    await expect(recipient.getByRole("button", { name: "Copy username" })).toBeVisible();
    await expect(recipient.getByRole("button", { name: "Copy title" })).toHaveCount(0);
    await page.getByRole("button", { name: "Delete now" }).focus();
    await page.keyboard.down("Space");
    await expect(page.getByRole("status")).toContainText("Share deleted.");
    await page.keyboard.up("Space");
    await recipient.goto(link.href);
    await expect(recipient.getByRole("alert")).toContainText("This share is unavailable.");
    expect([...violations, ...recipientViolations]).toEqual([]);
  } finally {
    await context.close();
  }
});

test("an image loses its metadata and a multichunk file downloads intact after the last view", async ({ page, browser }) => {
  const violations = await monitor(page.context());
  await page.goto("/");
  await page.getByRole("tab", { name: "Files" }).click();
  const image = png();
  const file = Buffer.from(Uint8Array.from({ length: 196_800 }, (_, index) => (index * 31) & 255));
  await page.locator("input[type=file]").setInputFiles([
    { name: "pixel.png", mimeType: "image/png", buffer: image.original },
    { name: "sample.bin", mimeType: "application/octet-stream", buffer: file },
  ]);
  await expect(page.locator(".thumbnail")).toBeVisible();
  const link = await createLink(page);
  const context = await browser.newContext();
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await recipient.getByRole("button", { name: "Reveal" }).click();
    const rendered = recipient.getByRole("img", { name: "pixel.png" });
    await expect(rendered).toHaveAttribute("src", /^blob:/);
    await expect.poll(() => rendered.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(1);
    for (const [name, original] of [["pixel.png", image.stripped], ["sample.bin", file]] as const) {
      const result = recipient.waitForEvent("download");
      await recipient.getByRole("link", { name: `Download ${name}` }).click();
      const download = await result;
      expect(download.suggestedFilename()).toBe(name);
      const stream = await download.createReadStream();
      const chunks: Buffer[] = [];
      for await (const chunk of stream as AsyncIterable<Buffer>) chunks.push(chunk);
      expect(Buffer.concat(chunks).equals(original)).toBe(true);
    }
    await expect(recipient.getByText("This was the last view.")).toBeVisible();
    expect([...violations, ...recipientViolations]).toEqual([]);
  } finally {
    await context.close();
  }
});
