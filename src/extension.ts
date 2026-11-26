import * as vscode from "vscode";
import { Session } from "./host/session";
import { VaultViewProvider } from "./host/provider";
import * as A from "./host/actions";
import { WrongPasswordError } from "./core/envelope";
import { WrongPinError, pinErrorText } from "./core/pin";
import { isPinFormat, isWeakPin } from "./shared/pin";

/** PIN entry in the command palette: accepts automatically at 6 digits, no Enter needed. */
function promptPin(s: Session): Promise<"unlocked" | "usePassword" | "cancel"> {
  return new Promise((resolve) => {
    const box = vscode.window.createInputBox();
    let result: "unlocked" | "usePassword" | "cancel" = "cancel";
    const finish = (r: typeof result) => { result = r; box.hide(); };
    box.title = "Authora PIN";
    box.prompt = "Enter your 6-digit PIN";
    box.password = true;
    box.ignoreFocusOut = true;
    box.buttons = [{ iconPath: new vscode.ThemeIcon("key"), tooltip: "Use master password" }];
    box.onDidTriggerButton(() => finish("usePassword"));
    box.onDidChangeValue(async (v) => {
      if (/\D/.test(v)) { box.validationMessage = "Digits only"; return; }
      box.validationMessage = undefined;
      if (!isPinFormat(v) || box.busy) return;
      box.busy = true;
      box.enabled = false;
      try {
        await s.unlockWithPin(v);
        finish("unlocked");
      } catch (e) {
        if (e instanceof WrongPinError && !e.erased && e.triesBeforeLock > 0) {
          box.value = "";
          box.validationMessage = pinErrorText(e);
        } else {
          vscode.window.showWarningMessage(`Authora: ${e instanceof WrongPinError ? pinErrorText(e) : (e as Error).message}`);
          finish("usePassword");
        }
      } finally {
        box.busy = false;
        box.enabled = true;
      }
    });
    box.onDidHide(() => { box.dispose(); resolve(result); });
    box.show();
  });
}

/** Ask for a new PIN twice. Escape skips; returns true if a PIN was set. */
async function askNewPin(s: Session, title: string): Promise<boolean> {
  const validateInput = (v: string) => !isPinFormat(v) ? "Enter 6 digits" : isWeakPin(v) ? "Too easy to guess" : undefined;
  const pin = await vscode.window.showInputBox({ title, prompt: "New 6-digit PIN (Escape to skip)", password: true, ignoreFocusOut: true, validateInput });
  if (!pin) return false;
  const again = await vscode.window.showInputBox({ title, prompt: "Repeat the PIN", password: true, ignoreFocusOut: true });
  if (again === undefined) return false;
  if (again !== pin) { vscode.window.showErrorMessage("PINs don't match"); return false; }
  await s.setPin(pin);
  return true;
}

export async function activate(ctx: vscode.ExtensionContext) {
  const s = new Session(ctx);
  const provider = new VaultViewProvider(ctx, s);
  ctx.subscriptions.push(s, vscode.window.registerWebviewViewProvider(VaultViewProvider.viewId, provider, {
    webviewOptions: { retainContextWhenHidden: false },
  }));

  // status bar
  const bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  const renderBar = () => {
    const open = s.store.isUnlocked;
    bar.text = open ? "$(unlock) 2FA" : "$(lock) 2FA";
    bar.tooltip = open ? "Authora: unlocked — click to copy a code" : "Authora: locked — click to unlock";
    bar.command = open ? "authora.copyCode" : "authora.unlock";
  };
  renderBar();
  bar.show();
  ctx.subscriptions.push(bar, s.onDidChange(renderBar));
  ctx.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("authora")) { s.syncRememberedKey(); s.fire(); }
  }));

  const focus = () => vscode.commands.executeCommand(`${VaultViewProvider.viewId}.focus`);

  /** Ensure unlocked, prompting in the command palette if needed. */
  const ensureUnlocked = async (): Promise<boolean> => {
    if (s.store.isUnlocked) return true;
    if (!s.store.exists()) { await focus(); return false; }
    if (s.pin.hasPin && s.pin.status().lockedMs === 0) {
      const r = await promptPin(s);
      if (r === "unlocked") return true;
      if (r === "cancel") return false;
    }
    const pw = await vscode.window.showInputBox({ prompt: "Authora master password", password: true, ignoreFocusOut: true });
    if (!pw) return false;
    try { await s.unlock(pw); return true; }
    catch (e) {
      vscode.window.showErrorMessage(e instanceof WrongPasswordError ? "Wrong password" : (e as Error).message);
      return false;
    }
  };

  const pickEntry = async (placeHolder: string) => {
    if (!(await ensureUnlocked())) return;
    const items = [...s.store.entries]
      .sort((a, b) => Number(b.pinned) - Number(a.pinned))
      .map((e) => ({ label: `${e.pinned ? "$(pinned) " : ""}${e.issuer || e.account || "Unnamed"}`, description: e.issuer ? e.account : "", detail: s.code(e).replace(/(\d{3})(?=\d)/g, "$1 "), e }));
    if (!items.length) { vscode.window.showInformationMessage("Vault is empty. Add an account first."); await focus(); return; }
    return (await vscode.window.showQuickPick(items, { placeHolder, matchOnDescription: true }))?.e;
  };

  const reg = (id: string, fn: (...a: unknown[]) => unknown) =>
    ctx.subscriptions.push(vscode.commands.registerCommand(id, async (...a) => {
      try { s.touch(); await fn(...a); } catch (e) { vscode.window.showErrorMessage(`Authora: ${(e as Error).message}`); }
    }));

  reg("authora.open", focus);
  reg("authora.unlock", async () => { if (await ensureUnlocked()) await focus(); });
  reg("authora.lock", () => s.lock());
  reg("authora.copyCode", async () => {
    const e = await pickEntry("Copy code for…");
    if (e) { await s.copyCode(e); vscode.window.setStatusBarMessage(`$(check) Copied ${A.label(e)} code`, 2500); }
  });
  reg("authora.insertCode", async () => {
    const ed = vscode.window.activeTextEditor;
    const e = await pickEntry("Insert code for…");
    if (e && ed) await ed.edit((b) => ed.selections.forEach((sel) => b.replace(sel, s.code(e))));
  });
  reg("authora.addFromUri", async () => {
    if (!(await ensureUnlocked())) return;
    const text = await vscode.window.showInputBox({ prompt: "Paste otpauth:// or otpauth-migration:// URI", ignoreFocusOut: true });
    if (!text) return;
    const r = await A.importText(s, text);
    if (r.kind === "done") vscode.window.showInformationMessage(r.message);
  });
  reg("authora.import", async () => {
    if (!(await ensureUnlocked())) return;
    const text = await A.pickImportFile();
    if (text === undefined) return;
    let r = await A.importText(s, text);
    if (r.kind === "needsPassword") {
      const pw = await vscode.window.showInputBox({ prompt: `Password for this ${r.format} backup`, password: true, ignoreFocusOut: true });
      if (!pw) return;
      r = await A.importText(s, text, pw);
    }
    if (r.kind === "done") vscode.window.showInformationMessage(r.message);
  });
  reg("authora.exportBackup", async () => {
    if (!(await ensureUnlocked())) return;
    const pw = await vscode.window.showInputBox({ prompt: "Password for the backup file (min 8 chars)", password: true, ignoreFocusOut: true, validateInput: (v) => v.length < 8 ? "Use at least 8 characters" : undefined });
    if (!pw) return;
    const again = await vscode.window.showInputBox({ prompt: "Repeat backup password", password: true, ignoreFocusOut: true });
    if (again !== pw) { vscode.window.showErrorMessage("Passwords don't match"); return; }
    if (await A.exportEncrypted(s, pw)) vscode.window.showInformationMessage("Encrypted backup saved");
  });
  reg("authora.chooseBackupFolder", async () => { if (await ensureUnlocked()) await A.chooseBackupFolder(s); });
  reg("authora.syncClock", async () => {
    const off = await A.syncClock(s);
    if (off === undefined) return;
    vscode.window.showInformationMessage(`Authora clock offset: ${off}s`);
  });
  reg("authora.changePassword", async () => {
    if (!(await ensureUnlocked())) return;
    const oldPw = await vscode.window.showInputBox({ prompt: "Current master password", password: true, ignoreFocusOut: true });
    if (!oldPw) return;
    const newPw = await vscode.window.showInputBox({ prompt: "New master password (min 8 chars)", password: true, ignoreFocusOut: true, validateInput: (v) => v.length < 8 ? "Use at least 8 characters" : undefined });
    if (!newPw) return;
    const again = await vscode.window.showInputBox({ prompt: "Repeat new password", password: true, ignoreFocusOut: true });
    if (again !== newPw) { vscode.window.showErrorMessage("Passwords don't match"); return; }
    const { hadPin } = await s.changePassword(oldPw, newPw);
    vscode.window.showInformationMessage("Master password changed");
    if (hadPin && await askNewPin(s, "Set your PIN again")) vscode.window.showInformationMessage("PIN set");
  });

  await s.tryRememberedUnlock();
  return { session: s }; // used by integration tests
}

export function deactivate() {}
