import * as vscode from "vscode";
import { Session } from "./host/session";
import { VaultViewProvider } from "./host/provider";
import * as A from "./host/actions";
import { WrongPasswordError } from "./core/envelope";

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
    await s.store.changePassword(oldPw, newPw);
    await s.syncRememberedKey();
    await s.autoBackup();
    vscode.window.showInformationMessage("Master password changed");
  });

  await s.tryRememberedUnlock();
  return { session: s }; // used by integration tests
}

export function deactivate() {}
