import {
  closeSync, copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync,
  statSync, unlinkSync, writeSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  Envelope, KdfCost, KdfParams, DEFAULT_KDF, WrongPasswordError,
  deriveKey, newKdf, openWithKey, sealWithKey, isEnvelope,
} from "./envelope";
import { Entry, newEntry } from "./otp";
import { randomUUID } from "node:crypto";

export class LockedError extends Error {
  constructor() { super("Vault is locked"); this.name = "LockedError"; }
}
export class ThrottledError extends Error {
  constructor(public waitMs: number) {
    super(`Too many attempts. Try again in ${Math.ceil(waitMs / 1000)}s`);
    this.name = "ThrottledError";
  }
}
/** The vault was re-keyed (password changed) by another window; this session was locked. */
export class VaultChangedError extends Error {
  constructor() {
    super("The vault password was changed in another window. Unlock again with the new password.");
    this.name = "VaultChangedError";
  }
}

export interface VaultData {
  entries: Entry[];
  lastBackupAt?: number;
}

/** Free attempts before throttling kicks in; then 5s, 10s, 20s ... capped at 5 min. */
const FREE_ATTEMPTS = 3;
const LOCK_STALE_MS = 10_000;
const LOCK_WAIT_MS = 5_000;

/** Give every entry a unique id (repairs vaults hit by duplicate ids from older imports). */
function uniqueIds(entries: Entry[]): Entry[] {
  const seen = new Set<string>();
  return entries.map((e) => {
    const n = newEntry(e);
    if (seen.has(n.id)) n.id = randomUUID();
    seen.add(n.id);
    return n;
  });
}

/**
 * Encrypted vault on disk. Several VS Code windows may hold the same file open, so every
 * mutation is a locked read-modify-write against the latest file contents (no lost updates).
 */
export class VaultStore {
  private key: Buffer | null = null;
  private kdf: KdfParams | null = null;
  private data: VaultData | null = null;
  private failures = 0;
  private blockedUntil = 0;
  /** ciphertext of the version we last read or wrote; used to skip needless reloads */
  private lastCt: string | null = null;

  constructor(
    readonly filePath: string,
    private readonly cost: KdfCost = DEFAULT_KDF,
    private readonly now: () => number = Date.now,
  ) {}

  exists(): boolean { return existsSync(this.filePath) || existsSync(this.bakPath); }
  get isUnlocked(): boolean { return this.key !== null; }
  get entries(): Entry[] { return this.unlocked().entries; }
  get lastBackupAt(): number | undefined { return this.unlocked().lastBackupAt; }

  private get bakPath() { return this.filePath + ".bak"; }
  private get lockPath() { return this.filePath + ".lock"; }

  private unlocked(): VaultData {
    if (!this.data || !this.key) throw new LockedError();
    return this.data;
  }

  private parse(path: string): Envelope {
    const env = JSON.parse(readFileSync(path, "utf8"));
    if (!isEnvelope(env)) throw new Error("Vault file is not recognised");
    return env;
  }

  /** Read the vault, falling back to the last good copy if the main file is damaged. */
  private readEnvelope(): Envelope {
    try {
      return this.parse(this.filePath);
    } catch (e) {
      if (existsSync(this.bakPath)) return this.parse(this.bakPath);
      throw e;
    }
  }

  // ---- cross-process lock (O_EXCL lock file) ----
  private async withFileLock<T>(fn: () => Promise<T> | T): Promise<T> {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const deadline = Date.now() + LOCK_WAIT_MS;
    let fd: number | null = null;
    while (fd === null) {
      try {
        fd = openSync(this.lockPath, "wx", 0o600);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try {
          if (Date.now() - statSync(this.lockPath).mtimeMs > LOCK_STALE_MS) unlinkSync(this.lockPath);
        } catch { /* raced with another remover */ }
        if (Date.now() > deadline) throw new Error("Vault is busy in another window. Try again.");
        await new Promise((r) => setTimeout(r, 25));
      }
    }
    try {
      return await fn();
    } finally {
      closeSync(fd);
      try { unlinkSync(this.lockPath); } catch { /* ignore */ }
    }
  }

  /** Durable atomic write: temp file + fsync + keep previous version as .bak + rename + dir fsync. */
  private writeEnvelope(env: Envelope) {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + ".tmp";
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, JSON.stringify(env));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (existsSync(this.filePath)) {
      try { this.parse(this.filePath); copyFileSync(this.filePath, this.bakPath); } catch { /* don't back up a damaged file */ }
    }
    renameSync(tmp, this.filePath);
    try {
      const dfd = openSync(dirname(this.filePath), "r");
      try { fsyncSync(dfd); } finally { closeSync(dfd); }
    } catch { /* directory fsync unsupported (e.g. Windows) */ }
    this.lastCt = env.ct;
  }

  /** Bring in-memory data up to date with the file. Locks and throws if the vault was re-keyed. */
  private syncFromDisk() {
    this.unlocked();
    if (!existsSync(this.filePath) && !existsSync(this.bakPath)) return;
    const env = this.readEnvelope();
    if (env.ct === this.lastCt) return;
    if (env.kdf.salt !== this.kdf!.salt) {
      this.lock();
      throw new VaultChangedError();
    }
    let raw: VaultData;
    try {
      raw = openWithKey(env, this.key!) as VaultData;
    } catch {
      this.lock();
      throw new VaultChangedError();
    }
    this.data = { ...raw, entries: uniqueIds(raw.entries || []) };
    this.lastCt = env.ct;
  }

  /** Re-read the file (e.g. after another window changed it). Returns false if this session got locked. */
  refresh(): boolean {
    if (!this.isUnlocked) return false;
    try { this.syncFromDisk(); return true; } catch { return this.isUnlocked; }
  }

  /** Locked read-modify-write against the latest version on disk. */
  private async transact<T>(fn: (d: VaultData) => T): Promise<T> {
    this.unlocked();
    return this.withFileLock(() => {
      this.syncFromDisk();
      const result = fn(this.data!);
      this.writeEnvelope(sealWithKey(this.data!, this.key!, this.kdf!));
      return result;
    });
  }

  async create(password: string): Promise<void> {
    if (this.exists()) throw new Error("Vault already exists");
    const kdf = newKdf(this.cost);
    const key = await deriveKey(password, kdf);
    await this.withFileLock(() => {
      if (existsSync(this.filePath)) throw new Error("Vault already exists");
      this.kdf = kdf;
      this.key = key;
      this.data = { entries: [] };
      this.writeEnvelope(sealWithKey(this.data, key, kdf));
    });
  }

  async unlock(password: string): Promise<void> {
    const wait = this.blockedUntil - this.now();
    if (wait > 0) throw new ThrottledError(wait);
    const env = this.readEnvelope();
    const key = await deriveKey(password, env.kdf);
    try {
      this.applyUnlock(env, key);
    } catch (e) {
      key.fill(0);
      if (e instanceof WrongPasswordError) {
        this.failures++;
        if (this.failures >= FREE_ATTEMPTS) {
          this.blockedUntil = this.now() + Math.min(5000 * 2 ** (this.failures - FREE_ATTEMPTS), 300_000);
        }
      }
      throw e;
    }
  }

  async unlockWithKey(key: Buffer): Promise<void> {
    this.applyUnlock(this.readEnvelope(), key);
  }

  private applyUnlock(env: Envelope, key: Buffer) {
    const raw = openWithKey(env, key) as VaultData;
    this.key = key;
    this.kdf = env.kdf;
    this.data = { ...raw, entries: uniqueIds(raw.entries || []) };
    this.lastCt = env.ct;
    this.failures = 0;
    this.blockedUntil = 0;
  }

  lock(): void {
    this.key?.fill(0);
    this.key = null;
    this.data = null;
    this.lastCt = null;
  }

  exportKey(): Buffer {
    if (!this.key) throw new LockedError();
    return Buffer.from(this.key);
  }

  async verifyPassword(password: string): Promise<boolean> {
    const env = this.readEnvelope();
    const key = await deriveKey(password, env.kdf);
    try { openWithKey(env, key); return true; }
    catch { return false; }
    finally { key.fill(0); }
  }

  async changePassword(oldPw: string, newPw: string): Promise<void> {
    this.unlocked();
    if (!(await this.verifyPassword(oldPw))) throw new WrongPasswordError();
    const kdf = newKdf(this.cost);
    const key = await deriveKey(newPw, kdf);
    await this.withFileLock(() => {
      this.syncFromDisk();
      this.key!.fill(0);
      this.kdf = kdf;
      this.key = key;
      this.writeEnvelope(sealWithKey(this.data!, key, kdf));
    });
  }

  /** Entries sealed with the vault's own key: a backup that opens with the vault password. */
  sealedBackup(): string {
    return JSON.stringify(sealWithKey({ entries: this.unlocked().entries }, this.key!, this.kdf!), null, 2);
  }

  async add(...entries: Entry[]): Promise<void> {
    await this.transact((d) => { d.entries.push(...entries); });
  }

  async update(id: string, patch: Partial<Entry>): Promise<Entry> {
    return this.transact((d) => {
      const i = d.entries.findIndex((e) => e.id === id);
      if (i < 0) throw new Error("Entry not found");
      d.entries[i] = newEntry({ ...d.entries[i], ...patch, id });
      return d.entries[i];
    });
  }

  /** HOTP: advance the counter based on the latest stored value. */
  async incrementCounter(id: string): Promise<void> {
    await this.transact((d) => {
      const e = d.entries.find((x) => x.id === id);
      if (!e) throw new Error("Entry not found");
      e.counter += 1;
    });
  }

  async remove(id: string): Promise<void> {
    await this.transact((d) => { d.entries = d.entries.filter((e) => e.id !== id); });
  }

  async togglePin(id: string): Promise<void> {
    await this.transact((d) => {
      const e = d.entries.find((x) => x.id === id);
      if (!e) throw new Error("Entry not found");
      e.pinned = !e.pinned;
    });
  }

  /** Reorder by id list; ids not mentioned keep their relative order at the end. */
  async reorder(ids: string[]): Promise<void> {
    await this.transact((d) => {
      const pos = new Map(ids.map((id, i) => [id, i]));
      d.entries = [...d.entries].sort((a, b) => (pos.get(a.id) ?? Infinity) - (pos.get(b.id) ?? Infinity));
    });
  }

  async setLastBackup(ts: number): Promise<void> {
    await this.transact((d) => { d.lastBackupAt = ts; });
  }
}
