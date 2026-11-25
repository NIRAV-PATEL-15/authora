import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  Envelope, KdfCost, KdfParams, DEFAULT_KDF, WrongPasswordError,
  deriveKey, newKdf, openWithKey, sealWithKey, isEnvelope,
} from "./envelope";
import { Entry, newEntry } from "./otp";

export class LockedError extends Error {
  constructor() { super("Vault is locked"); this.name = "LockedError"; }
}
export class ThrottledError extends Error {
  constructor(public waitMs: number) {
    super(`Too many attempts. Try again in ${Math.ceil(waitMs / 1000)}s`);
    this.name = "ThrottledError";
  }
}

export interface VaultData {
  entries: Entry[];
  lastBackupAt?: number;
}

/** Free attempts before throttling kicks in; then 5s, 10s, 20s ... capped at 5 min. */
const FREE_ATTEMPTS = 3;

export class VaultStore {
  private key: Buffer | null = null;
  private kdf: KdfParams | null = null;
  private data: VaultData | null = null;
  private failures = 0;
  private blockedUntil = 0;

  constructor(
    readonly filePath: string,
    private readonly cost: KdfCost = DEFAULT_KDF,
    private readonly now: () => number = Date.now,
  ) {}

  exists(): boolean { return existsSync(this.filePath); }
  get isUnlocked(): boolean { return this.key !== null; }

  get entries(): Entry[] { return this.unlocked().entries; }
  get lastBackupAt(): number | undefined { return this.unlocked().lastBackupAt; }

  private unlocked(): VaultData {
    if (!this.data || !this.key) throw new LockedError();
    return this.data;
  }

  private readEnvelope(): Envelope {
    const env = JSON.parse(readFileSync(this.filePath, "utf8"));
    if (!isEnvelope(env)) throw new Error("Vault file is not recognised");
    return env;
  }

  async create(password: string): Promise<void> {
    if (this.exists()) throw new Error("Vault already exists");
    this.kdf = newKdf(this.cost);
    this.key = await deriveKey(password, this.kdf);
    this.data = { entries: [] };
    await this.save();
  }

  async unlock(password: string): Promise<void> {
    const wait = this.blockedUntil - this.now();
    if (wait > 0) throw new ThrottledError(wait);
    const env = this.readEnvelope();
    const key = await deriveKey(password, env.kdf);
    try {
      this.applyUnlock(env, key);
    } catch (e) {
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
    this.data = { ...raw, entries: (raw.entries || []).map(newEntry) };
    this.failures = 0;
    this.blockedUntil = 0;
  }

  lock(): void {
    this.key?.fill(0);
    this.key = null;
    this.data = null;
  }

  exportKey(): Buffer {
    if (!this.key) throw new LockedError();
    return Buffer.from(this.key);
  }

  async verifyPassword(password: string): Promise<boolean> {
    const env = this.readEnvelope();
    try { openWithKey(env, await deriveKey(password, env.kdf)); return true; }
    catch { return false; }
  }

  async changePassword(oldPw: string, newPw: string): Promise<void> {
    this.unlocked();
    if (!(await this.verifyPassword(oldPw))) throw new WrongPasswordError();
    const kdf = newKdf(this.cost);
    const key = await deriveKey(newPw, kdf);
    this.key!.fill(0);
    this.kdf = kdf;
    this.key = key;
    await this.save();
  }

  async save(): Promise<void> {
    const data = this.unlocked();
    const env = sealWithKey(data, this.key!, this.kdf!);
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + ".tmp";
    writeFileSync(tmp, JSON.stringify(env), { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  async add(...entries: Entry[]): Promise<void> {
    this.unlocked().entries.push(...entries);
    await this.save();
  }

  async update(id: string, patch: Partial<Entry>): Promise<Entry> {
    const list = this.unlocked().entries;
    const i = list.findIndex((e) => e.id === id);
    if (i < 0) throw new Error("Entry not found");
    list[i] = newEntry({ ...list[i], ...patch, id });
    await this.save();
    return list[i];
  }

  async remove(id: string): Promise<void> {
    const d = this.unlocked();
    d.entries = d.entries.filter((e) => e.id !== id);
    await this.save();
  }

  async togglePin(id: string): Promise<void> {
    const e = this.unlocked().entries.find((x) => x.id === id);
    if (!e) throw new Error("Entry not found");
    e.pinned = !e.pinned;
    await this.save();
  }

  /** Reorder by id list; ids not mentioned keep their relative order at the end. */
  async reorder(ids: string[]): Promise<void> {
    const d = this.unlocked();
    const pos = new Map(ids.map((id, i) => [id, i]));
    d.entries = [...d.entries].sort(
      (a, b) => (pos.get(a.id) ?? Infinity) - (pos.get(b.id) ?? Infinity),
    );
    await this.save();
  }

  async setLastBackup(ts: number): Promise<void> {
    this.unlocked().lastBackupAt = ts;
    await this.save();
  }
}
