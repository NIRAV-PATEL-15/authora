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
/** `failures` counts PIN attempts not yet cleared by a success; `lockedAt` is when the current 1-minute lock began (0 = none). */
interface Attempts { failures: number; lockedAt: number }
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
/** The attempt couldn't be counted (e.g. the attempts file isn't writable), so the PIN isn't checked at all. */
export class PinUnavailableError extends Error {
  constructor() { super("PIN unlock is unavailable right now. Use your master password."); this.name = "PinUnavailableError"; }
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
    return { failures: a.failures, lockedMs: this.lockedMs(a) };
  }

  /** Remaining lock. A lock stamped in the future (clock moved back) is ignored, so a lock never outlives a minute. */
  private lockedMs(a: Attempts): number {
    const since = this.now() - a.lockedAt;
    return a.lockedAt > 0 && since >= 0 && since < PIN_LOCK_MS ? PIN_LOCK_MS - since : 0;
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
    try { await this.resetAttempts(); } catch { /* attempts file unwritable: nothing more to clear */ }
  }

  async resetAttempts(): Promise<void> {
    await this.withLock(() => this.writeAttempts({ failures: 0, lockedAt: 0 }));
  }

  async unlock(pin: string, vaultSalt: string, verify: (key: Buffer) => Promise<void>): Promise<void> {
    const s = await this.readSlot();
    if (!s || s.vaultSalt !== vaultSalt) { await this.remove(); throw new PinInvalidError(); }
    // Count the attempt under the lock *before* checking the PIN, so parallel guesses
    // (several windows, scripted messages) can't slip past the limit, and an attempt
    // that can't be counted is never checked.
    const failures = await this.reserveAttempt();
    let key: Buffer;
    try {
      key = Buffer.from(String(await open(s.env, pin)), "base64");
    } catch (e) {
      if (!(e instanceof WrongPasswordError)) { await this.releaseAttempt(); throw e; }
      if (failures >= PIN_MAX_FAILS) { await this.remove(); throw new WrongPinError(true, 0, failures); }
      throw new WrongPinError(false, (PIN_FAILS_PER_LOCK - (failures % PIN_FAILS_PER_LOCK)) % PIN_FAILS_PER_LOCK, failures);
    }
    try {
      await verify(key);
    } catch (e) {
      key.fill(0);
      if (e instanceof WrongPasswordError) { await this.remove(); throw new PinInvalidError(); }
      await this.releaseAttempt();
      throw e;
    }
    try { await this.resetAttempts(); } catch { /* already unlocked; a stale count must not undo that */ }
  }

  /** Throws PinLockedError while locked; otherwise records one attempt (locking at every 3rd) and returns the new count. */
  private async reserveAttempt(): Promise<number> {
    let out: number | PinLockedError;
    try {
      out = await this.withLock(() => {
        const a = this.readAttempts();
        const wait = this.lockedMs(a);
        if (wait > 0) return new PinLockedError(wait);
        a.failures += 1;
        a.lockedAt = a.failures % PIN_FAILS_PER_LOCK === 0 && a.failures < PIN_MAX_FAILS ? this.now() : 0;
        this.writeAttempts(a);
        return a.failures;
      });
    } catch {
      throw new PinUnavailableError();
    }
    if (out instanceof PinLockedError) throw out;
    return out;
  }

  /** Undo a reservation when the attempt failed for a reason other than the PIN. Best effort. */
  private async releaseAttempt(): Promise<void> {
    try {
      await this.withLock(() => {
        const a = this.readAttempts();
        a.failures = Math.max(0, a.failures - 1);
        if (a.failures % PIN_FAILS_PER_LOCK !== 0) a.lockedAt = 0;
        this.writeAttempts(a);
      });
    } catch { /* ignore */ }
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
      const lockedAt = Number.isFinite(a?.lockedAt) ? a.lockedAt : 0;
      return { failures, lockedAt };
    } catch {
      return { failures: 0, lockedAt: 0 };
    }
  }

  private writeAttempts(a: Attempts) {
    const tmp = this.attemptsFile + ".tmp";
    writeFileSync(tmp, JSON.stringify(a), { mode: 0o600 });
    renameSync(tmp, this.attemptsFile);
  }
}

/** User-facing text for a failed PIN unlock. */
export function pinErrorText(e: WrongPinError | PinLockedError | PinInvalidError): string {
  if (!(e instanceof WrongPinError) || e.erased) return e.message;
  if (e.failures >= PIN_MAX_FAILS - PIN_FAILS_PER_LOCK) return `Wrong PIN · ${PIN_MAX_FAILS - e.failures} more wrong PIN${PIN_MAX_FAILS - e.failures === 1 ? "" : "s"} will erase it`;
  return e.triesBeforeLock > 0
    ? `Wrong PIN · ${e.triesBeforeLock} tr${e.triesBeforeLock === 1 ? "y" : "ies"} before a 1-minute lock`
    : "Wrong PIN · PIN locked for 1 minute";
}
