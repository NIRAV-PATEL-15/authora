import * as vscode from "vscode";
import { randomBytes } from "node:crypto";
import { Session, cfg } from "./session";
import { HostMsg, ViewMsg } from "../shared/protocol";
import { ThrottledError } from "../core/vault";
import { WrongPasswordError } from "../core/envelope";
import { WrongBackupPasswordError } from "../core/importers";
import { newEntry, validateSecret } from "../core/otp";
import * as A from "./actions";

export class VaultViewProvider implements vscode.WebviewViewProvider {
  static readonly viewId = "authora.accounts";
  private view?: vscode.WebviewView;

  constructor(private readonly ctx: vscode.ExtensionContext, private readonly s: Session) {
    s.onDidChange(() => this.pushState());
  }

  resolveWebviewView(view: vscode.WebviewView) {
    this.view = view;
    const media = vscode.Uri.joinPath(this.ctx.extensionUri, "media");
    const dist = vscode.Uri.joinPath(this.ctx.extensionUri, "dist");
    view.webview.options = { enableScripts: true, localResourceRoots: [media, dist] };
    view.webview.html = this.html(view.webview);
    view.webview.onDidReceiveMessage((m: ViewMsg) => this.handle(m));
    view.onDidChangeVisibility(() => view.visible && this.pushState());
  }

  post(m: HostMsg) { this.view?.webview.postMessage(m); }
  pushState(throttledMs?: number) { this.post({ type: "state", state: this.s.viewState(throttledMs) }); }

  private find(id: string) {
    const e = this.s.store.entries.find((x) => x.id === id);
    if (!e) throw new Error("Account not found");
    return e;
  }

  private async handle(m: ViewMsg) {
    if (m.type !== "ready" && m.type !== "refresh") this.s.touch();
    const form = m.type;
    try {
      switch (m.type) {
        case "ready": this.pushState(); break;
        case "activity": break;
        case "create":
          if (m.password.length < 8) throw new Error("Use at least 8 characters");
          await this.s.create(m.password);
          break;
        case "unlock":
          if (m.remember !== cfg().rememberOnThisMachine) {
            await vscode.workspace.getConfiguration("authora").update("rememberOnThisMachine", m.remember, vscode.ConfigurationTarget.Global);
          }
          await this.s.unlock(m.password);
          break;
        case "lock": this.s.lock(); break;
        case "refresh":
          if (this.s.store.isUnlocked) this.post({ type: "codes", codes: this.s.codes() });
          break;
        case "copy": {
          await this.s.copyCode(this.find(m.id));
          const secs = cfg().clipboardClearSeconds;
          this.post({ type: "toast", text: secs > 0 ? `Copied · clears in ${secs}s` : "Copied" });
          break;
        }
        case "next": {
          const e = this.find(m.id);
          await this.s.mutate(() => this.s.store.update(e.id, { counter: e.counter + 1 }));
          break;
        }
        case "addManual": {
          const e = newEntry(m.entry);
          validateSecret(e);
          await this.s.mutate(() => this.s.store.add(e));
          this.post({ type: "done", form });
          this.post({ type: "toast", text: `Added ${A.label(e)}`, kind: "ok" });
          break;
        }
        case "importText": {
          const r = await A.importText(this.s, m.text, m.password);
          if (r.kind === "needsPassword") this.post({ type: "needPassword", form: "import", text: m.text, format: r.format });
          else { this.post({ type: "done", form }); this.post({ type: "toast", text: r.message, kind: "ok" }); }
          break;
        }
        case "importFile": {
          const text = await A.pickImportFile();
          if (text === undefined) break;
          const r = await A.importText(this.s, text);
          if (r.kind === "needsPassword") this.post({ type: "needPassword", form: "import", text, format: r.format });
          else { this.post({ type: "done", form: "importText" }); this.post({ type: "toast", text: r.message, kind: "ok" }); }
          break;
        }
        case "update":
          await this.s.mutate(() => this.s.store.update(m.id, { issuer: m.patch.issuer, account: m.patch.account }));
          this.post({ type: "done", form });
          break;
        case "delete": {
          const e = this.find(m.id);
          const ok = await vscode.window.showWarningMessage(
            `Delete ${A.label(e)}? Make sure 2FA is turned off on that site first, or you may be locked out.`,
            { modal: true }, "Delete");
          if (ok === "Delete") {
            await this.s.mutate(() => this.s.store.remove(m.id));
            this.post({ type: "done", form });
          }
          break;
        }
        case "pin": await this.s.mutate(() => this.s.store.togglePin(m.id)); break;
        case "reorder": await this.s.mutate(() => this.s.store.reorder(m.ids)); break;
        case "showQr": {
          const e = this.find(m.id);
          this.post({ type: "qr", id: e.id, svg: await A.qrSvg(e), label: A.label(e) });
          break;
        }
        case "exportEncrypted":
          if (m.password.length < 8) throw new Error("Use at least 8 characters");
          if (await A.exportEncrypted(this.s, m.password)) {
            this.post({ type: "done", form });
            this.post({ type: "toast", text: "Encrypted backup saved", kind: "ok" });
          }
          break;
        case "exportPlain":
          if (await A.exportPlain(this.s)) this.post({ type: "toast", text: "Exported", kind: "ok" });
          break;
        case "backupNow": {
          const f = await this.s.autoBackup(true);
          this.s.fire();
          if (f) this.post({ type: "toast", text: "Backed up", kind: "ok" });
          break;
        }
        case "chooseBackupFolder":
          if (await A.chooseBackupFolder(this.s)) this.post({ type: "toast", text: "Auto-backup on", kind: "ok" });
          break;
        case "changePassword":
          if (m.newPassword.length < 8) throw new Error("Use at least 8 characters");
          await this.s.store.changePassword(m.oldPassword, m.newPassword);
          await this.s.syncRememberedKey();
          await this.s.autoBackup();
          this.post({ type: "done", form });
          this.post({ type: "toast", text: "Password changed", kind: "ok" });
          break;
        case "syncClock": {
          const off = await A.syncClock(this.s);
          this.post({ type: "toast", text: `Clock synced (offset ${off >= 0 ? "+" : ""}${off}s)`, kind: "ok" });
          break;
        }
        case "ignoreInsight": await this.s.ignore(m.id); break;
        case "setSetting":
          await vscode.workspace.getConfiguration("authora").update(m.key, m.value, vscode.ConfigurationTarget.Global);
          if (m.key === "rememberOnThisMachine") await this.s.syncRememberedKey();
          this.s.fire();
          break;
      }
    } catch (err) {
      if (err instanceof ThrottledError) { this.pushState(err.waitMs); this.post({ type: "error", form, text: err.message }); return; }
      const text = err instanceof WrongPasswordError ? (form === "changePassword" ? "Current password is wrong" : "Wrong password")
        : err instanceof WrongBackupPasswordError ? "Wrong backup password"
        : (err as Error).message || String(err);
      this.post({ type: "error", form, text });
      if (!["create", "unlock", "addManual", "importText", "exportEncrypted", "changePassword", "update"].includes(form)) {
        this.post({ type: "toast", text, kind: "error" });
      }
    }
  }

  private html(w: vscode.Webview): string {
    const nonce = randomBytes(16).toString("base64");
    const css = w.asWebviewUri(vscode.Uri.joinPath(this.ctx.extensionUri, "media", "main.css"));
    const js = w.asWebviewUri(vscode.Uri.joinPath(this.ctx.extensionUri, "dist", "webview.js"));
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${w.cspSource} 'unsafe-inline'; img-src ${w.cspSource} data: blob:; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${css}"></head>
<body><div id="app"></div><script nonce="${nonce}" src="${js}"></script></body></html>`;
  }
}
