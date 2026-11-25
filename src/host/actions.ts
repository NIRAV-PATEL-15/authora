import * as vscode from "vscode";
import { chmodSync, writeFileSync } from "node:fs";
import * as QRCode from "qrcode";
import { Session } from "./session";
import { importAny, dedupe, ImportResult } from "../core/importers";
import { makeBackup } from "../core/backup";
import { fetchOffset } from "../core/timesync";
import { toOtpauth } from "../core/uri";
import { Entry } from "../core/otp";

export type ImportOutcome = { kind: "needsPassword"; format: string } | { kind: "done"; message: string };

export async function importText(s: Session, text: string, password?: string): Promise<ImportOutcome> {
  const r: ImportResult = await importAny(text, password);
  if (r.needsPassword) return { kind: "needsPassword", format: r.format };
  const { added, duplicates } = dedupe(s.store.entries, r.entries);
  if (!added.length && !duplicates) {
    throw new Error(r.failed ? `Nothing imported: ${r.failed} item(s) were invalid` : "No accounts found in that input");
  }
  if (added.length) await s.mutate(() => s.store.add(...added));
  const parts = [`Added ${added.length} account${added.length === 1 ? "" : "s"}`];
  if (duplicates) parts.push(`${duplicates} already in vault`);
  if (r.failed) parts.push(`${r.failed} invalid`);
  return { kind: "done", message: parts.join(" · ") };
}

export async function pickImportFile(): Promise<string | undefined> {
  const uris = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: "Import",
    filters: { "Backups": ["json", "txt", "authora", "2fas"], "All files": ["*"] },
  });
  if (!uris?.length) return;
  return Buffer.from(await vscode.workspace.fs.readFile(uris[0])).toString("utf8");
}

/** Write a sensitive file and force owner-only permissions even when overwriting an existing file. */
function writePrivate(path: string, content: string) {
  writeFileSync(path, content, { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* not supported on this filesystem */ }
}

function stamp() {
  return new Date().toISOString().slice(0, 10);
}

export async function exportEncrypted(s: Session, password: string): Promise<boolean> {
  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`authora-backup-${stamp()}.authora`),
    filters: { "Authora backup": ["authora"] },
  });
  if (!uri) return false;
  writePrivate(uri.fsPath, await makeBackup(s.store.entries, password));
  await s.store.setLastBackup(Date.now());
  s.fire();
  return true;
}

export async function exportPlain(s: Session): Promise<boolean> {
  const ok = await vscode.window.showWarningMessage(
    "This writes every secret in plain text. Anyone who gets the file can generate your codes.",
    { modal: true },
    "Export unencrypted",
  );
  if (ok !== "Export unencrypted") return false;
  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`authora-otpauth-${stamp()}.txt`),
    filters: { "Text": ["txt"] },
  });
  if (!uri) return false;
  writePrivate(uri.fsPath, s.store.entries.map(toOtpauth).join("\n") + "\n");
  return true;
}

export async function chooseBackupFolder(s: Session): Promise<string | undefined> {
  const uris = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, openLabel: "Use for auto-backup" });
  if (!uris?.length) return;
  await vscode.workspace.getConfiguration("authora").update("autoBackupFolder", uris[0].fsPath, vscode.ConfigurationTarget.Global);
  const file = await s.autoBackup(true);
  s.fire();
  return file;
}

/** Offsets beyond this need explicit confirmation (a TLS-intercepting proxy could otherwise skew codes). */
export const MAX_SILENT_OFFSET = 300;

export async function syncClock(s: Session): Promise<number | undefined> {
  const off = await fetchOffset();
  if (Math.abs(off) > MAX_SILENT_OFFSET) {
    const ok = await vscode.window.showWarningMessage(
      `The server's clock differs from yours by ${off} seconds. Usually this means your system clock is wrong; fixing the system clock is better. Apply this offset to Authora anyway?`,
      { modal: true }, "Apply offset");
    if (ok !== "Apply offset") return undefined;
  }
  await s.setOffset(off);
  return off;
}

export async function qrSvg(e: Entry): Promise<string> {
  return QRCode.toString(toOtpauth(e), { type: "svg", margin: 1, errorCorrectionLevel: "M" });
}

export function label(e: Entry): string {
  return e.issuer ? (e.account ? `${e.issuer} (${e.account})` : e.issuer) : e.account || "Unnamed";
}
