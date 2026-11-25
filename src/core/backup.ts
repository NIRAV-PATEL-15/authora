import { mkdirSync, readdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_KDF, KdfCost, seal } from "./envelope";
import { Entry } from "./otp";

const PATTERN = /^vault2fa-\d{8}-\d{6}\.vault2fa$/;
const pad = (n: number) => String(n).padStart(2, "0");

export function backupFileName(d: Date): string {
  return `vault2fa-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.vault2fa`;
}

/** Encrypt entries with `password` into a portable backup string. */
export async function makeBackup(entries: Entry[], password: string, cost: KdfCost = DEFAULT_KDF): Promise<string> {
  return JSON.stringify(await seal({ entries }, password, cost), null, 2);
}

/** Write a timestamped backup (already-encrypted `content`) into `dir`, deleting older ones beyond `keep`. */
export function writeBackupFile(dir: string, content: string, keep: number, when = new Date()): string {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, backupFileName(when));
  writeFileSync(file + ".tmp", content, { mode: 0o600 });
  renameSync(file + ".tmp", file);
  const ours = readdirSync(dir).filter((f) => PATTERN.test(f)).sort();
  for (const old of ours.slice(0, Math.max(0, ours.length - Math.max(1, keep)))) unlinkSync(join(dir, old));
  return file;
}

export async function writeBackup(
  dir: string, entries: Entry[], password: string, keep: number, when = new Date(), cost: KdfCost = DEFAULT_KDF,
): Promise<string> {
  return writeBackupFile(dir, await makeBackup(entries, password, cost), keep, when);
}
