import * as vscode from "vscode";
import { join } from "node:path";
import { VaultStore } from "../core/vault";
import { Entry, generateCode } from "../core/otp";
import { advise } from "../core/advisor";
import { writeBackupFile } from "../core/backup";
import { PinManager } from "../core/pin";
import type { EntryView, ViewState } from "../shared/protocol";

const KEY_SECRET = "authora.rememberedKey";
const OFFSET_KEY = "authora.clockOffset";
const IGNORED_KEY = "authora.ignoredInsights";
/** Set by an explicit or automatic lock: the remembered key must not reopen the vault until a password unlock. */
const REQUIRE_PW_KEY = "authora.requirePassword";
/** SecretStorage entry holding the vault key wrapped with the quick-unlock PIN. */
const PIN_SECRET = "authora.pin";
/** The "set a PIN" offer has been shown (and set up or dismissed). */
const PIN_OFFER_KEY = "authora.pinOfferShown";

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
  readonly pin: PinManager;
  /** A vault was just created in this window: offer the PIN as the next setup step. */
  private justCreated = false;
  private lastActivity = Date.now();
  private timer: NodeJS.Timeout;
  private clipTimer?: NodeJS.Timeout;
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  constructor(private readonly ctx: vscode.ExtensionContext) {
    this.store = new VaultStore(join(ctx.globalStorageUri.fsPath, "vault.json"));
    const secrets = ctx.secrets;
    this.pin = new PinManager(
      {
        get: async () => secrets.get(PIN_SECRET),
        store: async (v) => secrets.store(PIN_SECRET, v),
        delete: async () => secrets.delete(PIN_SECRET),
      },
      join(ctx.globalStorageUri.fsPath, "pin-attempts.json"),
      (fn) => this.store.withLock(fn),
    );
    void this.pin.load().then(() => this.fire());
    this.timer = setInterval(() => this.checkAutoLock(), 10_000);
    // Another VS Code window may change the vault file; pick up its changes (or lock if it was re-keyed).
    const w = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(ctx.globalStorageUri, "vault.json"));
    const onExternal = () => { if (this.store.isUnlocked) { this.store.refresh(); this.fire(); } };
    // A PIN set or erased in another window.
    const onSecret = secrets.onDidChange((e) => { if (e.key === PIN_SECRET) void this.pin.load().then(() => this.fire()); });
    this.watcher = vscode.Disposable.from(w, w.onDidChange(onExternal), w.onDidCreate(onExternal), onSecret);
  }
  private readonly watcher: vscode.Disposable;

  dispose() {
    clearInterval(this.timer);
    this.watcher.dispose();
    if (this.clipTimer) clearTimeout(this.clipTimer);
    this.store.lock();
    this.changed.dispose();
  }

  get offset(): number {
    const v = this.ctx.globalState.get<number>(OFFSET_KEY, 0);
    return Number.isFinite(v) ? v : 0;
  }
  async setOffset(v: number) { await this.ctx.globalState.update(OFFSET_KEY, v); this.fire(); }

  touch() { this.lastActivity = Date.now(); }
  fire() { this.changed.fire(); }

  private checkAutoLock() {
    const mins = cfg().autoLockMinutes;
    if (this.store.isUnlocked && mins > 0 && Date.now() - this.lastActivity > mins * 60_000) void this.lock();
  }

  /** Try the OS-keychain key at startup when the user opted in. */
  async tryRememberedUnlock() {
    if (!cfg().rememberOnThisMachine || !this.store.exists()) return;
    if (this.ctx.globalState.get<boolean>(REQUIRE_PW_KEY, false)) return;
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
    this.justCreated = true;
    await this.ctx.globalState.update(REQUIRE_PW_KEY, false);
    this.touch();
    await this.syncRememberedKey();
    this.fire();
  }

  async unlock(password: string) {
    await this.store.unlock(password);
    try { await this.pin.resetAttempts(); } catch { /* attempts file unwritable: PIN limits stay as they were */ }
    await this.afterUnlock();
  }

  /** Quick unlock with the 6-digit PIN (throws PinLockedError / WrongPinError / PinInvalidError). */
  async unlockWithPin(pin: string) {
    await this.pin.unlock(pin, this.store.currentSalt(), (key) => this.store.unlockWithKey(key));
    await this.afterUnlock();
  }

  private async afterUnlock() {
    await this.ctx.globalState.update(REQUIRE_PW_KEY, false);
    this.touch();
    await this.syncRememberedKey();
    this.fire();
  }

  async setPin(pin: string) {
    const key = this.store.exportKey();
    try { await this.pin.set(key, pin, this.store.currentSalt()); } finally { key.fill(0); }
    await this.dismissPinOffer();
  }

  async removePin() {
    await this.pin.remove();
    this.fire();
  }

  async dismissPinOffer() {
    this.justCreated = false;
    await this.ctx.globalState.update(PIN_OFFER_KEY, true);
    this.fire();
  }

  /** Change the master password. A stored PIN can't open the new key, so it is erased (`hadPin` says whether to ask again). */
  async changePassword(oldPw: string, newPw: string): Promise<{ hadPin: boolean }> {
    const hadPin = this.pin.hasPin;
    await this.store.changePassword(oldPw, newPw);
    if (hadPin) await this.pin.remove();
    await this.syncRememberedKey();
    await this.autoBackup();
    this.fire();
    return { hadPin };
  }

  /** Lock now. Until the next password unlock, the remembered key (if any) will not auto-unlock. */
  async lock() {
    if (!this.store.isUnlocked) return;
    this.store.lock();
    this.fire();
    await this.ctx.globalState.update(REQUIRE_PW_KEY, true);
  }

  /** Run a mutation, then auto-backup and notify the UI. */
  async mutate(fn: () => Promise<unknown>) {
    this.touch();
    try {
      await fn();
    } catch (e) {
      this.fire(); // e.g. VaultChangedError locked us: show the lock screen
      throw e;
    }
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
    if (!this.store.isUnlocked) {
      return { screen: "locked", throttledMs, remember: cfg().rememberOnThisMachine, pin: this.pin.hasPin ? this.pin.status() : undefined };
    }
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
      settings: { hideCodes: c.hideCodes, autoLockMinutes: c.autoLockMinutes, rememberOnThisMachine: c.rememberOnThisMachine, autoBackupFolder: c.autoBackupFolder, pinSet: this.pin.hasPin },
      offerPin: this.pin.hasPin ? undefined
        : this.justCreated ? "afterCreate"
        : this.ctx.globalState.get<boolean>(PIN_OFFER_KEY, false) ? undefined : "newFeature",
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
