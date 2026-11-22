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
  await page.getByRole("button", { name: "Seal and get link" }).click();
  await expect(page.getByRole("textbox", { name: "Share link" })).toBeVisible();
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
    await expect(recipient.getByRole("button", { name: "Break the seal" })).toBeVisible();
    expect(recipient.url()).toBe(`${link.origin}${link.pathname}`);
    expect(stateChanges).toEqual([]);
  } finally {
    recipient.context().off("request", track);
  }
}

async function expectNoHorizontalOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(page.viewportSize()?.width);
}

test("production secret fields disable spellcheck before and after showing a password", async ({ page }) => {
  async function off(selector: string) {
    const field = page.locator(selector);
    await expect(field).toHaveAttribute("spellcheck", "false");
    expect(await field.evaluate((element: HTMLInputElement | HTMLTextAreaElement) => element.spellcheck)).toBe(false);
  }

  await page.goto("/");
  await off("#share-text");
  await page.getByRole("tab", { name: "Login" }).click();
  for (const name of ["title", "username", "password", "url", "totp", "note"]) {
    await off(`#login-${name}`);
  }
  await page.getByRole("button", { name: "Show password" }).click();
  await expect(page.locator("#login-password")).toHaveAttribute("type", "text");
  await off("#login-password");

  await page.locator("#login-title").fill("Synthetic login");
  await page.getByRole("button", { name: "Add a password" }).click();
  await off("#share-password");
  await page.getByRole("button", { name: "Show share password" }).click();
  await expect(page.locator("#share-password")).toHaveAttribute("type", "text");
  await off("#share-password");
  await page.getByRole("button", { name: "Generate share password" }).click();
  await expect(page.locator("#share-password")).toHaveValue(/^[A-Za-z0-9_-]{43}$/);
  const link = await createLink(page);
  await off("#created-link");
  await page.getByRole("button", { name: "Send the key separately" }).click();
  const key = page.locator('input[aria-label="Share key"]');
  await expect(key).toHaveValue(link.hash.slice(1));
  await off('input[aria-label="Share key"]');
  await expect(page.locator("#created-link")).not.toHaveValue(/#/);
  const separate = new URL((await page.locator("#created-link").inputValue()).replace(/^https:/, "http:"));

  await page.goto(separate.href);
  await off("#reveal-key");
  await page.locator("#reveal-key").fill(link.hash.slice(1));
  await page.getByRole("button", { name: "Use key" }).click();
  await off("#reveal-password");
  expect(page.url()).toBe(separate.href);
});

test("the desk and its controls fit the requested widths", async ({ page }) => {
  for (const width of [320, 390, 768, 1280]) {
    await page.setViewportSize({ width, height: 800 });
    await page.goto("/");
    const action = page.getByRole("button", { name: "Seal and get link" });
    await expect(action).toBeDisabled();
    await expect(action).toHaveAttribute("title", "Write something first");
    await expectNoHorizontalOverflow(page);
    const footer = await page.locator("footer").boundingBox();
    const main = await page.locator("main").boundingBox();
    expect(footer!.y - main!.y - main!.height).toBeLessThan(32);
    expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBe(800);

    const views = page.getByRole("button", { name: "Views, 1 view" });
    await views.focus();
    await page.keyboard.press("Enter");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await expect(page.getByRole("button", { name: "3 views", exact: true })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "Views, 3 views" })).toBeFocused();

    const expiry = page.getByRole("button", { name: "Expiry, 1 day" });
    await expiry.click();
    await expect(page.getByRole("group", { name: "Expiry" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.keyboard.press("Escape");
    await expect(expiry).toBeFocused();
    await page.getByRole("button", { name: "Add a password" }).click();
    await expect(page.getByLabel("Share password", { exact: true })).toBeFocused();
    await expectNoHorizontalOverflow(page);

    const login = page.getByRole("tab", { name: "Login" });
    const files = page.getByRole("tab", { name: "Files" });
    await page.getByRole("tab", { name: "Text" }).focus();
    await page.keyboard.press("ArrowRight");
    await expect(login).toBeFocused();
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.keyboard.press("ArrowRight");
    await expect(files).toBeFocused();
    await expect(page.getByRole("button", { name: "Choose files" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  }
});

test("text renders as text after a click and the final view burns the share", async ({ page, browser }) => {
  const violations = await monitor(page.context());
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Expiry, 1 day" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Views, 1 view" })).toBeVisible();
  await expect(page.locator("script[src][integrity]")).toHaveCount(1);
  await expect(page.locator("link[rel=stylesheet][integrity]")).toHaveCount(1);
  const text = "<img src=x onerror=alert(1)>\nSecond line.";
  await page.getByRole("textbox", { name: "Secret text" }).fill(text);
  const link = await createLink(page);
  await expect(page.getByText("Burns after 1 view or in 1 day.")).toBeVisible();
  await expectNoHorizontalOverflow(page);
  const context = await browser.newContext({ viewport: { width: 390, height: 800 } });
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await expect(recipient.getByText("Someone sealed this for you. It burns after this view.")).toBeVisible();
    await expectNoHorizontalOverflow(recipient);
    await expect(recipient.locator("pre")).toHaveCount(0);
    await recipient.getByRole("button", { name: "Break the seal" }).click();
    await expect(recipient.locator("pre")).toHaveText(text);
    await expect(recipient.getByText("This was the last view.")).toBeVisible();
    await expectNoHorizontalOverflow(recipient);
    await recipient.getByRole("button", { name: "Close share" }).click();
    await expect(recipient.getByText("Nothing here. The link has burned or expired.")).toBeVisible();
    await expect(recipient.locator("pre")).toHaveCount(0);
    await recipient.goto(link.href);
    await expect(recipient.getByText("Nothing here. The link has burned or expired.")).toBeVisible();
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
  await page.getByRole("button", { name: "Views, 1 view" }).click();
  await page.getByRole("button", { name: "3 views", exact: true }).click();
  await page.getByRole("button", { name: "Add a password" }).click();
  const sharePassword = "Synthetic share password";
  await page.getByLabel("Share password", { exact: true }).fill(sharePassword);
  const link = await createLink(page);
  const context = await browser.newContext();
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await expect(recipient.getByText("Someone sealed this for you. 3 views left.")).toBeVisible();
    await recipient.getByLabel("Share password").fill("Wrong password");
    await recipient.getByRole("button", { name: "Break the seal" }).click();
    await expect(recipient.getByRole("alert")).toContainText("Wrong password. 7 tries left before this burns.");
    const metadata = await context.request.get(`${link.origin}/api/v1/shares/${link.pathname.slice(3)}`);
    expect((await metadata.json()).views_left).toBe(3);
    await recipient.getByLabel("Share password").fill(sharePassword);
    await recipient.getByRole("button", { name: "Break the seal" }).click();
    await expect(recipient.getByText("operator", { exact: true })).toBeVisible();
    await expect(recipient.locator(".reveal-meta").getByRole("status")).toMatchAriaSnapshot(`- status: 2 views left.`);
    await expect(recipient.getByText(loginPassword, { exact: true })).toHaveCount(0);
    await recipient.getByRole("button", { name: "Show password" }).click();
    await expect(recipient.getByText(loginPassword, { exact: true })).toBeVisible();
    await expect(recipient.getByRole("button", { name: "Copy username" })).toBeVisible();
    await expect(recipient.getByRole("button", { name: "Copy title" })).toHaveCount(0);
    await page.getByRole("button", { name: "Burn now" }).focus();
    await page.keyboard.down("Space");
    await expect(page.getByRole("status")).toContainText("Share burned.");
    await page.keyboard.up("Space");
    await recipient.goto(link.href);
    await expect(recipient.getByText("Nothing here. The link has burned or expired.")).toBeVisible();
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
  await expect(page.getByText("Metadata kept", { exact: false })).toHaveCount(1);
  const link = await createLink(page);
  const context = await browser.newContext();
  try {
    const recipientViolations = await monitor(context);
    const recipient = await context.newPage();
    await openLink(recipient, link);
    await recipient.getByRole("button", { name: "Break the seal" }).click();
    await expect(recipient.getByText(/server keeps the files for up to 10 minutes/)).toBeVisible();
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
