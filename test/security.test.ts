// Regression tests for the security review findings.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultStore, VaultChangedError } from "../src/core/vault";
import { FAST_KDF_FOR_TESTS, seal, isEnvelope } from "../src/core/envelope";
import { importAny } from "../src/core/importers";
import { newEntry } from "../src/core/otp";
import { isValidViewMsg } from "../src/shared/validate";

const P = FAST_KDF_FOR_TESTS;
const SECRET = "JBSWY3DPEHPK3PXP";
let file: string;
beforeEach(() => { file = join(mkdtempSync(join(tmpdir(), "authora-sec-")), "vault.json"); });

async function twoWindows() {
  const a = new VaultStore(file, P);
  await a.create("password1");
  const b = new VaultStore(file, P);
  await b.unlock("password1");
  return { a, b };
}

describe("H1: two windows on the same vault", () => {
  it("does not lose an account added in another window", async () => {
    const { a, b } = await twoWindows();
    await a.add(newEntry({ issuer: "GitHub", secret: SECRET }));
    await b.add(newEntry({ issuer: "AWS", secret: SECRET }));
    const fresh = new VaultStore(file, P);
    await fresh.unlock("password1");
    expect(fresh.entries.map((e) => e.issuer).sort()).toEqual(["AWS", "GitHub"]);
  });

  it("a password change in one window cannot be reverted by the other", async () => {
    const { a, b } = await twoWindows();
    await a.changePassword("password1", "password2");
    await expect(b.togglePin("nope")).rejects.toBeInstanceOf(VaultChangedError);
    expect(b.isUnlocked).toBe(false);
    const fresh = new VaultStore(file, P);
    await expect(fresh.unlock("password1")).rejects.toThrow();
    await fresh.unlock("password2");
  });

  it("refresh() picks up the other window's changes", async () => {
    const { a, b } = await twoWindows();
    await a.add(newEntry({ issuer: "X", secret: SECRET }));
    expect(b.refresh()).toBe(true);
    expect(b.entries.map((e) => e.issuer)).toEqual(["X"]);
  });

  it("HOTP counter increments from the latest stored value", async () => {
    const { a, b } = await twoWindows();
    const e = newEntry({ type: "hotp", issuer: "H", secret: SECRET });
    await a.add(e);
    b.refresh();
    await a.incrementCounter(e.id);
    await b.incrementCounter(e.id);
    b.refresh();
    expect(b.entries[0].counter).toBe(2);
  });
});

describe("M1: re-importing a backup", () => {
  it("assigns fresh ids so deleting one copy keeps the other", async () => {
    const v = new VaultStore(file, P);
    await v.create("password1");
    const orig = newEntry({ issuer: "GitHub", account: "me", secret: SECRET });
    await v.add(orig);
    const backup = v.sealedBackup();
    await v.update(orig.id, { account: "renamed" });
    const r = await importAny(backup, "password1");
    expect(r.entries[0].id).not.toBe(orig.id);
    await v.add(...r.entries);
    await v.remove(orig.id);
    expect(v.entries).toHaveLength(1);
  });

  it("repairs duplicate ids already stored in a vault", async () => {
    const dup = newEntry({ issuer: "A", secret: SECRET });
    const env = await seal({ entries: [dup, { ...dup, issuer: "B" }] }, "password1", P);
    writeFileSync(file, JSON.stringify(env));
    const v = new VaultStore(file, P);
    await v.unlock("password1");
    expect(new Set(v.entries.map((e) => e.id)).size).toBe(2);
  });
});

describe("L1: hostile backup envelopes", () => {
  it("rejects absurd Argon2 parameters without running them", async () => {
    const good = await seal({ entries: [] }, "pw", P);
    for (const kdf of [{ t: 1_000_000 }, { m: 4_194_304 }, { p: 64 }, { t: 1.5 }, { salt: "AAAA" }]) {
      const evil = { ...good, kdf: { ...good.kdf, ...kdf } };
      expect(isEnvelope(evil)).toBe(false);
      const started = Date.now();
      await expect(importAny(JSON.stringify(evil), "pw")).rejects.toThrow(/unsafe|invalid/i);
      expect(Date.now() - started).toBeLessThan(500);
    }
  });
  it("rejects a wrong-length IV", async () => {
    const good = await seal({ entries: [] }, "pw", P);
    expect(isEnvelope({ ...good, iv: Buffer.alloc(16).toString("base64") })).toBe(false);
  });
});

describe("L3: crash safety", () => {
  it("falls back to the previous good copy if vault.json is corrupted", async () => {
    const v = new VaultStore(file, P);
    await v.create("password1");
    await v.add(newEntry({ issuer: "Keep", secret: SECRET }));
    await v.add(newEntry({ issuer: "Keep2", secret: SECRET }));
    writeFileSync(file, ""); // simulated torn write
    const fresh = new VaultStore(file, P);
    await fresh.unlock("password1");
    expect(fresh.entries.map((e) => e.issuer)).toContain("Keep");
    expect(JSON.parse(readFileSync(file + ".bak", "utf8")).v).toBe(1);
  });
});

describe("input validation", () => {
  it("normalises bad numeric fields and caps long text", () => {
    const e = newEntry({ period: 0.5, digits: NaN, issuer: "x".repeat(5000), secret: SECRET });
    expect(e.period).toBe(30);
    expect(e.digits).toBe(6);
    expect(e.issuer.length).toBe(128);
  });
  it("rejects malformed webview messages", () => {
    expect(isValidViewMsg({ type: "copy", id: "abc" })).toBe(true);
    expect(isValidViewMsg({ type: "copy", id: 42 })).toBe(false);
    expect(isValidViewMsg({ type: "setSetting", key: "autoBackupFolder", value: "\\\\evil\\share" })).toBe(false);
    expect(isValidViewMsg({ type: "setSetting", key: "autoLockMinutes", value: -1 })).toBe(false);
    expect(isValidViewMsg({ type: "unlock", password: "x" })).toBe(false);
    expect(isValidViewMsg({ type: "__proto__" })).toBe(false);
    expect(isValidViewMsg(null)).toBe(false);
  });
});

describe("L4: clock offset", () => {
  it("a NaN offset falls back to no offset instead of breaking codes", async () => {
    const { generateCode } = await import("../src/core/otp");
    const e = newEntry({ secret: SECRET });
    expect(generateCode(e, 59_000, NaN)).toBe(generateCode(e, 59_000, 0));
  });
});
