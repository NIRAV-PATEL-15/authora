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

// ---------------- PinManager ----------------
import { writeFileSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { WrongPasswordError } from "../src/core/envelope";
import {
  PinManager, SecretSlot, PinLockedError, PinInvalidError, WrongPinError, PIN_LOCK_MS,
} from "../src/core/pin";

class MemSlot implements SecretSlot {
  v: string | undefined;
  failGet = false;
  async get() { if (this.failGet) throw new Error("keychain unavailable"); return this.v; }
  async store(v: string) { this.v = v; }
  async delete() { this.v = undefined; }
}

const SALT = "c2FsdHNhbHRzYWx0c2FsdA==";
let clock = 1_000_000;
function setup() {
  const dir = mkdtempSync(join(tmpdir(), "authora-pinm-"));
  const vault = new VaultStore(join(dir, "vault.json"), FAST_KDF_FOR_TESTS);
  const slot = new MemSlot();
  const attempts = join(dir, "pin-attempts.json");
  const pm = new PinManager(slot, attempts, (fn) => vault.withLock(fn), FAST_KDF_FOR_TESTS, () => clock);
  return { pm, slot, attempts };
}
const KEY = randomBytes(32);
const okVerify = async () => {};
async function wrong(pm: PinManager) {
  try { await pm.unlock("000001", SALT, okVerify); } catch (e) { return e; }
  throw new Error("expected failure");
}

describe("PinManager", () => {
  beforeEach(() => { clock = 1_000_000; });

  it("set then unlock with the right PIN hands the vault key to verify", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    expect(pm.hasPin).toBe(true);
    let got: Buffer | undefined;
    await pm.unlock("482913", SALT, async (k) => { got = k; });
    expect(got && got.equals(KEY)).toBe(true);
  });

  it("wrong PINs count down, then lock for a minute", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    const e1 = await wrong(pm) as WrongPinError;
    expect(e1).toBeInstanceOf(WrongPinError);
    expect(e1.triesBeforeLock).toBe(2);
    expect(((await wrong(pm)) as WrongPinError).triesBeforeLock).toBe(1);
    const e3 = (await wrong(pm)) as WrongPinError;
    expect(e3.triesBeforeLock).toBe(0);
    expect(e3.erased).toBe(false);
    expect(pm.status().lockedMs).toBe(PIN_LOCK_MS);
    await expect(pm.unlock("482913", SALT, okVerify)).rejects.toBeInstanceOf(PinLockedError);
  });

  it("locks again at 6 and erases the PIN at 9", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    for (let i = 0; i < 3; i++) await wrong(pm);
    clock += PIN_LOCK_MS + 1;
    for (let i = 0; i < 2; i++) await wrong(pm);
    expect(((await wrong(pm)) as WrongPinError).failures).toBe(6);
    expect(pm.status().lockedMs).toBe(PIN_LOCK_MS);
    clock += PIN_LOCK_MS + 1;
    await wrong(pm); await wrong(pm);
    const last = (await wrong(pm)) as WrongPinError;
    expect(last.erased).toBe(true);
    expect(pm.hasPin).toBe(false);
    expect(pm.status()).toEqual({ lockedMs: 0, failures: 0 });
  });

  it("a correct PIN resets the failure count", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    await wrong(pm); await wrong(pm);
    await pm.unlock("482913", SALT, okVerify);
    expect(pm.status().failures).toBe(0);
  });

  it("resetAttempts clears an active lock (password unlock)", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    for (let i = 0; i < 3; i++) await wrong(pm);
    await pm.resetAttempts();
    expect(pm.status()).toEqual({ lockedMs: 0, failures: 0 });
  });

  it("a re-keyed vault (different salt) invalidates the PIN without counting a failure", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    await wrong(pm);
    await expect(pm.unlock("482913", "b3RoZXJzYWx0b3RoZXJzYQ==", okVerify)).rejects.toBeInstanceOf(PinInvalidError);
    expect(pm.hasPin).toBe(false);
  });

  it("a key that no longer opens the vault invalidates the PIN", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    await expect(pm.unlock("482913", SALT, async () => { throw new WrongPasswordError(); })).rejects.toBeInstanceOf(PinInvalidError);
    expect(pm.hasPin).toBe(false);
  });

  it("an unavailable keychain means no PIN", async () => {
    const { pm, slot } = setup();
    await pm.set(KEY, "482913", SALT);
    slot.failGet = true;
    await pm.load();
    expect(pm.hasPin).toBe(false);
  });

  it("a corrupt attempts file counts as no failures", () => {
    const { pm, attempts } = setup();
    writeFileSync(attempts, "{x");
    expect(pm.status()).toEqual({ lockedMs: 0, failures: 0 });
  });

  it("a lock stamped in the future (clock moved back) never holds the PIN locked past a minute", () => {
    const { pm, attempts } = setup();
    writeFileSync(attempts, JSON.stringify({ failures: 3, lockedAt: clock + 10 * 3600_000 }));
    expect(pm.status().lockedMs).toBeLessThanOrEqual(PIN_LOCK_MS);
    clock += PIN_LOCK_MS + 1;
    expect(pm.status().lockedMs).toBe(0);
  });

  it("a PIN lock expires within a minute even if the clock moved back after it started", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    for (let i = 0; i < 3; i++) await wrong(pm);
    clock -= 3600_000;
    clock += PIN_LOCK_MS + 1;
    expect(pm.status().lockedMs).toBe(0);
    await pm.unlock("482913", SALT, okVerify);
  });

  it("parallel guesses cannot get past the 3-attempt limit", async () => {
    const { pm } = setup();
    await pm.set(KEY, "482913", SALT);
    const guesses = Array.from({ length: 30 }, (_, i) => String(500000 + i * 7));
    const results = await Promise.allSettled(guesses.map((g) => pm.unlock(g, SALT, okVerify)));
    const checked = results.filter((r) => !(r.status === "rejected" && r.reason instanceof PinLockedError));
    expect(checked.length).toBeLessThanOrEqual(3);
  });

  it("refuses PIN attempts when they can't be counted", async () => {
    const { pm, attempts } = setup();
    await pm.set(KEY, "482913", SALT);
    mkdirSync(attempts.replace(/\.json$/, ".json.tmp"));
    for (let i = 0; i < 5; i++) {
      const e = await pm.unlock("000001", SALT, okVerify).catch((x) => x);
      expect(e).not.toBeInstanceOf(WrongPinError);
      expect(String(e.message)).toMatch(/master password/);
    }
    expect(pm.hasPin).toBe(true);
  });

  it("set rejects weak and malformed PINs", async () => {
    const { pm } = setup();
    await expect(pm.set(KEY, "123456", SALT)).rejects.toThrow("Too easy to guess");
    await expect(pm.set(KEY, "12345", SALT)).rejects.toThrow();
    expect(pm.hasPin).toBe(false);
  });
});

describe("pinErrorText", () => {
  it("counts down to the lock, then towards erasure", async () => {
    const { pinErrorText } = await import("../src/core/pin");
    expect(pinErrorText(new WrongPinError(false, 2, 1))).toBe("Wrong PIN · 2 tries before a 1-minute lock");
    expect(pinErrorText(new WrongPinError(false, 1, 2))).toBe("Wrong PIN · 1 try before a 1-minute lock");
    expect(pinErrorText(new WrongPinError(false, 0, 3))).toBe("Wrong PIN · PIN locked for 1 minute");
    expect(pinErrorText(new WrongPinError(false, 0, 6))).toBe("Wrong PIN · 3 more wrong PINs will erase it");
    expect(pinErrorText(new WrongPinError(false, 1, 8))).toBe("Wrong PIN · 1 more wrong PIN will erase it");
    expect(pinErrorText(new WrongPinError(true, 0, 9))).toBe("Too many wrong PINs. PIN erased. Unlock with your master password.");
  });
});
