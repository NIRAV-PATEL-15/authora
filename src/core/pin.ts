// Quick-unlock PIN: the vault key wrapped with a 6-digit PIN, kept in the OS keychain (via a SecretSlot).
// The vault file itself is never encrypted with the PIN. Wrong guesses are limited:
// every 3rd failure locks the PIN for a minute, the 9th erases it.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { DEFAULT_KDF, Envelope, KdfCost, WrongPasswordError, open, seal } from "./envelope";
import { isPinFormat, isWeakPin } from "../shared/pin";

export const PIN_LOCK_MS = 60_000;
export const PIN_FAILS_PER_LOCK = 3;
export const PIN_MAX_FAILS = 9;

/** Where the wrapped key lives (VS Code SecretStorage in the extension, memory in tests). */
export interface SecretSlot {
  get(): Promise<string | undefined>;
  store(v: string): Promise<void>;
  delete(): Promise<void>;
}

export interface PinStatus { lockedMs: number; failures: number }
interface Attempts { failures: number; lockedUntil: number }
interface Slot { vaultSalt: string; env: Envelope }

export class PinLockedError extends Error {
  constructor(public waitMs: number) {
    super(`PIN locked. Try again in ${Math.ceil(waitMs / 1000)}s`);
    this.name = "PinLockedError";
  }
}
export class PinInvalidError extends Error {
  constructor() { super("PIN no longer valid. Use your master password."); this.name = "PinInvalidError"; }
}
export class WrongPinError extends Error {
  constructor(public erased: boolean, public triesBeforeLock: number, public failures: number) {
    super(erased ? "Too many wrong PINs. PIN erased. Unlock with your master password." : "Wrong PIN");
    this.name = "WrongPinError";
  }
}

export class PinManager {
  private has = false;

  constructor(
    private readonly slot: SecretSlot,
    private readonly attemptsFile: string,
    private readonly withLock: <T>(fn: () => Promise<T> | T) => Promise<T>,
    private readonly cost: KdfCost = DEFAULT_KDF,
    private readonly now: () => number = Date.now,
  ) {}

  get hasPin(): boolean { return this.has; }

  async load(): Promise<void> {
    this.has = !!(await this.readSlot());
  }

  status(): PinStatus {
    const a = this.readAttempts();
    return { failures: a.failures, lockedMs: Math.min(PIN_LOCK_MS, Math.max(0, a.lockedUntil - this.now())) };
  }

  async set(key: Buffer, pin: string, vaultSalt: string): Promise<void> {
    if (!isPinFormat(pin)) throw new Error("PIN must be 6 digits");
    if (isWeakPin(pin)) throw new Error("Too easy to guess");
    const env = await seal(key.toString("base64"), pin, this.cost);
    await this.slot.store(JSON.stringify({ vaultSalt, env } satisfies Slot));
    this.has = true;
    await this.resetAttempts();
  }

  async remove(): Promise<void> {
    try { await this.slot.delete(); } catch { /* keychain unavailable: nothing to erase */ }
    this.has = false;
    await this.resetAttempts();
  }

  async resetAttempts(): Promise<void> {
    await this.withLock(() => this.writeAttempts({ failures: 0, lockedUntil: 0 }));
  }

  async unlock(pin: string, vaultSalt: string, verify: (key: Buffer) => Promise<void>): Promise<void> {
    const wait = this.status().lockedMs;
    if (wait > 0) throw new PinLockedError(wait);
    const s = await this.readSlot();
    if (!s || s.vaultSalt !== vaultSalt) { await this.remove(); throw new PinInvalidError(); }
    let key: Buffer;
    try {
      key = Buffer.from(String(await open(s.env, pin)), "base64");
    } catch (e) {
      if (!(e instanceof WrongPasswordError)) throw e;
      throw await this.recordFailure();
    }
    try {
      await verify(key);
    } catch (e) {
      if (e instanceof WrongPasswordError) { await this.remove(); throw new PinInvalidError(); }
      throw e;
    }
    await this.resetAttempts();
  }

  private async recordFailure(): Promise<WrongPinError> {
    const failures = await this.withLock(() => {
      const a = this.readAttempts();
      a.failures += 1;
      if (a.failures % PIN_FAILS_PER_LOCK === 0 && a.failures < PIN_MAX_FAILS) a.lockedUntil = this.now() + PIN_LOCK_MS;
      this.writeAttempts(a);
      return a.failures;
    });
    if (failures >= PIN_MAX_FAILS) { await this.remove(); return new WrongPinError(true, 0, failures); }
    return new WrongPinError(false, (PIN_FAILS_PER_LOCK - (failures % PIN_FAILS_PER_LOCK)) % PIN_FAILS_PER_LOCK, failures);
  }

  private async readSlot(): Promise<Slot | undefined> {
    try {
      const raw = await this.slot.get();
      if (!raw) return undefined;
      const s = JSON.parse(raw) as Slot;
      return typeof s?.vaultSalt === "string" && s.env ? s : undefined;
    } catch {
      return undefined;
    }
  }

  private readAttempts(): Attempts {
    try {
      const a = JSON.parse(readFileSync(this.attemptsFile, "utf8"));
      const failures = Number.isInteger(a?.failures) && a.failures >= 0 ? a.failures : 0;
      const lockedUntil = Number.isFinite(a?.lockedUntil) ? a.lockedUntil : 0;
      return { failures, lockedUntil };
    } catch {
      return { failures: 0, lockedUntil: 0 };
    }
  }

  private writeAttempts(a: Attempts) {
    const tmp = this.attemptsFile + ".tmp";
    writeFileSync(tmp, JSON.stringify(a), { mode: 0o600 });
    renameSync(tmp, this.attemptsFile);
  }
}
