import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultStore } from "../src/core/vault";
import { FAST_KDF_FOR_TESTS } from "../src/core/envelope";
import { isPinFormat, isWeakPin } from "../src/shared/pin";

let file: string;
beforeEach(() => { file = join(mkdtempSync(join(tmpdir(), "authora-pin-")), "vault.json"); });

describe("pin rules", () => {
  it("accepts exactly six digits", () => {
    expect(isPinFormat("482913")).toBe(true);
    for (const bad of ["12345", "1234567", "12a456", " 123456", "123456\n", 123456, undefined, null]) {
      expect(isPinFormat(bad)).toBe(false);
    }
  });

  it("flags easy-to-guess PINs", () => {
    for (const w of ["000000", "999999", "123456", "654321", "012345", "987654", "121212", "123123", "112233"]) {
      expect(isWeakPin(w)).toBe(true);
    }
    for (const ok of ["482913", "730215", "246810", "135792"]) expect(isWeakPin(ok)).toBe(false);
  });

  it("currentSalt reads the vault salt while locked", async () => {
    const v = new VaultStore(file, FAST_KDF_FOR_TESTS);
    await v.create("password1");
    v.lock();
    expect(v.currentSalt()).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("withLock runs the callback and returns its value", async () => {
    const v = new VaultStore(file, FAST_KDF_FOR_TESTS);
    expect(await v.withLock(() => 42)).toBe(42);
  });
});
