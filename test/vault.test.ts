import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { seal, open, WrongPasswordError, FAST_KDF_FOR_TESTS } from "../src/core/envelope";
import { VaultStore, LockedError, ThrottledError } from "../src/core/vault";
import { newEntry } from "../src/core/otp";

const P = FAST_KDF_FOR_TESTS;

describe("envelope", () => {
  it("round trips", async () => {
    const env = await seal({ a: 1 }, "pw", P);
    expect(env.v).toBe(1);
    expect(env.kdf.alg).toBe("argon2id");
    expect(await open(env, "pw")).toEqual({ a: 1 });
  });
  it("wrong password throws WrongPasswordError", async () => {
    const env = await seal({ a: 1 }, "pw", P);
    await expect(open(env, "nope")).rejects.toBeInstanceOf(WrongPasswordError);
  });
  it("tampered ciphertext throws", async () => {
    const env = await seal({ a: 1 }, "pw", P);
    const ct = Buffer.from(env.ct, "base64");
    ct[0] ^= 1;
    await expect(open({ ...env, ct: ct.toString("base64") }, "pw")).rejects.toBeInstanceOf(WrongPasswordError);
  });
  it("default params are m=65536 t=3 p=1", async () => {
    const env = await seal({}, "pw");
    expect(env.kdf).toMatchObject({ m: 65536, t: 3, p: 1 });
  });
});

describe("VaultStore", () => {
  let file: string;
  beforeEach(() => {
    file = join(mkdtempSync(join(tmpdir(), "v2fa-")), "vault.json");
  });

  it("create, add, lock, unlock", async () => {
    const v = new VaultStore(file, P);
    expect(v.exists()).toBe(false);
    await v.create("secret pw");
    await v.add(newEntry({ issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP" }));
    expect(readFileSync(file, "utf8")).not.toContain("JBSWY3DPEHPK3PXP");
    v.lock();
    expect(v.isUnlocked).toBe(false);
    expect(() => v.entries).toThrow(LockedError);
    const v2 = new VaultStore(file, P);
    await v2.unlock("secret pw");
    expect(v2.entries.map((e) => e.issuer)).toEqual(["GitHub"]);
  });

  it("wrong password leaves file untouched", async () => {
    const v = new VaultStore(file, P);
    await v.create("pw");
    const before = readFileSync(file);
    v.lock();
    await expect(v.unlock("bad")).rejects.toBeInstanceOf(WrongPasswordError);
    expect(readFileSync(file)).toEqual(before);
  });

  it("throttles after repeated failures", async () => {
    let now = 1000;
    const v = new VaultStore(file, P, () => now);
    await v.create("pw");
    v.lock();
    for (let i = 0; i < 3; i++) await expect(v.unlock("bad")).rejects.toBeInstanceOf(WrongPasswordError);
    await expect(v.unlock("pw")).rejects.toBeInstanceOf(ThrottledError);
    now += 60_000;
    await v.unlock("pw");
    expect(v.isUnlocked).toBe(true);
  });

  it("unlock with exported key", async () => {
    const v = new VaultStore(file, P);
    await v.create("pw");
    const key = v.exportKey();
    v.lock();
    await v.unlockWithKey(key);
    expect(v.isUnlocked).toBe(true);
  });

  it("changePassword re-encrypts", async () => {
    const v = new VaultStore(file, P);
    await v.create("old");
    await v.add(newEntry({ secret: "JBSWY3DPEHPK3PXP" }));
    await expect(v.changePassword("wrong", "new")).rejects.toBeInstanceOf(WrongPasswordError);
    await v.changePassword("old", "new");
    v.lock();
    await expect(v.unlock("old")).rejects.toBeInstanceOf(WrongPasswordError);
    await v.unlock("new");
    expect(v.entries).toHaveLength(1);
  });

  it("update, pin, reorder, remove", async () => {
    const v = new VaultStore(file, P);
    await v.create("pw");
    const a = newEntry({ issuer: "A", secret: "JBSWY3DPEHPK3PXP" });
    const b = newEntry({ issuer: "B", secret: "JBSWY3DPEHPK3PXP" });
    await v.add(a);
    await v.add(b);
    await v.reorder([b.id, a.id]);
    expect(v.entries.map((e) => e.issuer)).toEqual(["B", "A"]);
    await v.update(a.id, { issuer: "A2" });
    await v.togglePin(a.id);
    expect(v.entries.find((e) => e.id === a.id)).toMatchObject({ issuer: "A2", pinned: true });
    await v.remove(b.id);
    expect(v.entries).toHaveLength(1);
  });

  it("atomic write leaves no temp file and survives garbage temp", async () => {
    const v = new VaultStore(file, P);
    await v.create("pw");
    writeFileSync(file + ".tmp", "garbage");
    await v.add(newEntry({ secret: "JBSWY3DPEHPK3PXP" }));
    expect(existsSync(file + ".tmp")).toBe(false);
    JSON.parse(readFileSync(file, "utf8"));
  });
});
