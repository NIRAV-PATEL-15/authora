import * as vscode from "vscode";
import { join } from "node:path";
import { VaultStore } from "../core/vault";
import { Entry, generateCode } from "../core/otp";
import { advise } from "../core/advisor";
import { writeBackupFile } from "../core/backup";
import type { EntryView, ViewState } from "../shared/protocol";

const KEY_SECRET = "authora.rememberedKey";
const OFFSET_KEY = "authora.clockOffset";
const IGNORED_KEY = "authora.ignoredInsights";

export function cfg() {
  const c = vscode.workspace.getConfiguration("authora");
  return {
    autoLockMinutes: c.get<number>("autoLockMinutes", 15),
    clipboardClearSeconds: c.get<number>("clipboardClearSeconds", 30),
    rememberOnThisMachine: c.get<boolean>("rememberOnThisMachine", false),
    autoBackupFolder: c.get<string>("autoBackupFolder", ""),
    backupKeep: c.get<number>("backupKeep", 10),
    hideCodes: c.get<boolean>("hideCodes", false),
  };
}

/** Owns the vault lifecycle: lock state, auto-lock, remembered key, clipboard, auto-backup. */
export class Session implements vscode.Disposable {
  readonly store: VaultStore;
  private lastActivity = Date.now();
  private timer: NodeJS.Timeout;
  private clipTimer?: NodeJS.Timeout;
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  constructor(private readonly ctx: vscode.ExtensionContext) {
    this.store = new VaultStore(join(ctx.globalStorageUri.fsPath, "vault.json"));
    this.timer = setInterval(() => this.checkAutoLock(), 10_000);
  }

  dispose() {
    clearInterval(this.timer);
    if (this.clipTimer) clearTimeout(this.clipTimer);
    this.store.lock();
    this.changed.dispose();
  }

  get offset(): number { return this.ctx.globalState.get<number>(OFFSET_KEY, 0); }
  async setOffset(v: number) { await this.ctx.globalState.update(OFFSET_KEY, v); this.fire(); }

  touch() { this.lastActivity = Date.now(); }
  fire() { this.changed.fire(); }

  private checkAutoLock() {
    const mins = cfg().autoLockMinutes;
    if (this.store.isUnlocked && mins > 0 && Date.now() - this.lastActivity > mins * 60_000) this.lock();
  }

  /** Try the OS-keychain key at startup when the user opted in. */
  async tryRememberedUnlock() {
    if (!cfg().rememberOnThisMachine || !this.store.exists()) return;
    const b64 = await this.ctx.secrets.get(KEY_SECRET);
    if (!b64) return;
    try {
      await this.store.unlockWithKey(Buffer.from(b64, "base64"));
      this.touch();
      this.fire();
    } catch {
      await this.ctx.secrets.delete(KEY_SECRET);
    }
  }

  async syncRememberedKey() {
    if (cfg().rememberOnThisMachine && this.store.isUnlocked) {
      await this.ctx.secrets.store(KEY_SECRET, this.store.exportKey().toString("base64"));
    } else if (!cfg().rememberOnThisMachine) {
      await this.ctx.secrets.delete(KEY_SECRET);
    }
  }

  async create(password: string) {
    await this.store.create(password);
    this.touch();
    await this.syncRememberedKey();
    this.fire();
  }

  async unlock(password: string) {
    await this.store.unlock(password);
    this.touch();
    await this.syncRememberedKey();
    this.fire();
  }

  lock() {
    if (!this.store.isUnlocked) return;
    this.store.lock();
    this.fire();
  }

  /** Run a mutation, then auto-backup and notify the UI. */
  async mutate(fn: () => Promise<unknown>) {
    this.touch();
    await fn();
    await this.autoBackup();
    this.fire();
  }

  async autoBackup(force = false): Promise<string | undefined> {
    const { autoBackupFolder, backupKeep } = cfg();
    if (!autoBackupFolder || !this.store.isUnlocked) {
      if (force) throw new Error("Choose an auto-backup folder first");
      return;
    }
    try {
      const file = writeBackupFile(autoBackupFolder, this.store.sealedBackup(), backupKeep);
      await this.store.setLastBackup(Date.now());
      return file;
    } catch (e) {
      vscode.window.showWarningMessage(`Authora auto-backup failed: ${(e as Error).message}`);
      if (force) throw e;
    }
  }

  code(e: Entry): string {
    try { return generateCode(e, Date.now(), this.offset); } catch { return ""; }
  }

  async copyCode(e: Entry): Promise<string> {
    const code = this.code(e);
    if (!code) throw new Error("This account's secret is invalid");
    await vscode.env.clipboard.writeText(code);
    this.touch();
    const secs = cfg().clipboardClearSeconds;
    if (this.clipTimer) clearTimeout(this.clipTimer);
    if (secs > 0) {
      this.clipTimer = setTimeout(async () => {
        if ((await vscode.env.clipboard.readText()) === code) await vscode.env.clipboard.writeText("");
      }, secs * 1000);
    }
    return code;
  }

  ignored(): string[] { return this.ctx.globalState.get<string[]>(IGNORED_KEY, []); }
  async ignore(id: string) { await this.ctx.globalState.update(IGNORED_KEY, [...new Set([...this.ignored(), id])]); this.fire(); }

  viewState(throttledMs?: number): ViewState {
    if (!this.store.exists()) return { screen: "setup" };
    if (!this.store.isUnlocked) return { screen: "locked", throttledMs, remember: cfg().rememberOnThisMachine };
    const c = cfg();
    const entries: EntryView[] = this.store.entries.map((e) => ({
      id: e.id, type: e.type, issuer: e.issuer, account: e.account, period: e.period, digits: e.digits,
      algorithm: e.algorithm, pinned: e.pinned, counterBased: e.type === "hotp" || e.type === "hhex", code: this.code(e),
    }));
    return {
      screen: "unlocked",
      entries,
      offset: this.offset,
      lastBackupAt: this.store.lastBackupAt,
      settings: { hideCodes: c.hideCodes, autoLockMinutes: c.autoLockMinutes, rememberOnThisMachine: c.rememberOnThisMachine, autoBackupFolder: c.autoBackupFolder },
      insights: advise({
        entryCount: entries.length, autoLockMinutes: c.autoLockMinutes, lastBackupAt: this.store.lastBackupAt,
        rememberOnThisMachine: c.rememberOnThisMachine, ignored: this.ignored(), now: Date.now(),
      }),
    };
  }

  codes(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const e of this.store.entries) out[e.id] = this.code(e);
    return out;
  }
}
