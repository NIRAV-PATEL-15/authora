import * as CryptoJS from "crypto-js";
import { Entry, OtpType, OtpAlgorithm, newEntry, validateSecret } from "./otp";
import { parseOtpauth, splitLabel } from "./uri";
import { parseMigration } from "./migration";
import { isEnvelope, looksLikeEnvelope, open } from "./envelope";
import type { VaultData } from "./vault";

export interface ImportResult {
  entries: Entry[];
  failed: number;
  /** The data is encrypted and no (or no) password was given. */
  needsPassword?: boolean;
  format: string;
}

export class WrongBackupPasswordError extends Error {
  constructor() { super("Wrong backup password"); this.name = "WrongBackupPasswordError"; }
}

function tryEntry(p: Partial<Entry>): Entry | null {
  try {
    // Never trust ids from a file: a re-imported backup must not collide with live entries.
    const e = newEntry({ ...p, id: undefined });
    validateSecret(e);
    return e;
  } catch {
    return null;
  }
}

function collect(parts: Partial<Entry>[], format: string): ImportResult {
  const entries: Entry[] = [];
  let failed = 0;
  for (const p of parts) {
    const e = tryEntry(p);
    if (e) entries.push(e); else failed++;
  }
  return { entries, failed, format };
}

function fromLines(text: string): ImportResult {
  const entries: Entry[] = [];
  let failed = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    try {
      if (/^otpauth-migration:/i.test(line)) entries.push(...parseMigration(line));
      else if (/^otpauth:/i.test(line)) entries.push(parseOtpauth(line));
    } catch {
      failed++;
    }
  }
  return { entries, failed, format: "otpauth" };
}

const ALG = (s: unknown): OtpAlgorithm | undefined => {
  const v = String(s || "").toUpperCase().replace("-", "");
  return v === "SHA1" || v === "SHA256" || v === "SHA512" ? v : undefined;
};
const TYPE = (s: unknown): OtpType | undefined => {
  const v = String(s || "").toLowerCase();
  return (["totp", "hotp", "battle", "steam", "hex", "hhex"] as const).find((t) => t === v);
};

function looksLikeSecret(s: string): boolean {
  return s.length >= 8 && (/^[a-z2-7]+=*$/i.test(s) || /^[0-9a-f]+$/i.test(s) || /^(blz-|bliz-|stm-)/.test(s));
}

function cryptoJsDecrypt(ct: string, pass: string): string | null {
  try {
    const s = CryptoJS.AES.decrypt(ct, pass).toString(CryptoJS.enc.Utf8);
    return s && looksLikeSecret(s) ? s : null;
  } catch {
    return null;
  }
}

/** Backups from the Chrome "Authenticator" extension (and its rebrands). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fromChrome(obj: Record<string, any>, password?: string): ImportResult {
  const items = Object.entries(obj).filter(([k, v]) => k !== "key" && v && typeof v === "object" && v.secret);
  const anyEncrypted = items.some(([, v]) => v.encrypted);
  if (anyEncrypted && !password) return { entries: [], failed: 0, needsPassword: true, format: "chrome" };

  let passphrase = password;
  if (anyEncrypted && obj.key && typeof obj.key.enc === "string") {
    // newer format: random key wrapped with the password; secrets encrypted with key (hex string)
    try { passphrase = CryptoJS.AES.decrypt(obj.key.enc, password!).toString(); } catch { passphrase = ""; }
  }

  const parts: Partial<Entry>[] = [];
  let failed = 0;
  let decryptedAny = false;
  for (const [, v] of items) {
    let secret: string | null = String(v.secret);
    if (v.encrypted) {
      secret = passphrase ? cryptoJsDecrypt(secret, passphrase) : null;
      if (!secret) { failed++; continue; }
      decryptedAny = true;
    }
    let type = TYPE(v.type);
    const pre = /^(blz-|bliz-|stm-)(.*)$/.exec(secret);
    if (pre) {
      type = pre[1] === "stm-" ? "steam" : "battle";
      secret = pre[2];
    }
    parts.push({
      type, secret, issuer: v.issuer, account: v.account, algorithm: ALG(v.algorithm),
      digits: v.digits, period: v.period, counter: v.counter, pinned: v.pinned,
      _index: Number(v.index) || 0,
    } as Partial<Entry>);
  }
  if (anyEncrypted && !decryptedAny) throw new WrongBackupPasswordError();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  parts.sort((a: any, b: any) => a._index - b._index);
  const r = collect(parts, "chrome");
  r.failed += failed;
  return r;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fromAndOtp(arr: any[]): ImportResult {
  return collect(arr.map((v) => {
    const label = splitLabel(String(v.label || ""));
    return {
      type: TYPE(v.type) ?? "totp", secret: v.secret, issuer: v.issuer || label.issuer,
      account: label.account, algorithm: ALG(v.algorithm), digits: v.digits, period: v.period, counter: v.counter,
    };
  }), "andOTP");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function from2fas(obj: any): ImportResult {
  if (!Array.isArray(obj.services) || (!obj.services.length && obj.servicesEncrypted)) {
    throw new Error("Encrypted 2FAS backups are not supported. Export without a password.");
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return collect(obj.services.map((s: any) => ({
    type: TYPE(s.otp?.tokenType) ?? "totp", secret: s.secret, issuer: s.otp?.issuer || s.name,
    account: s.otp?.account || s.otp?.label || "", algorithm: ALG(s.otp?.algorithm),
    digits: s.otp?.digits, period: s.otp?.period, counter: s.otp?.counter,
  })), "2FAS");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fromAegis(obj: any): ImportResult {
  if (typeof obj.db === "string") throw new Error("Encrypted Aegis backups are not supported. Export unencrypted.");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return collect(obj.db.entries.map((v: any) => ({
    type: TYPE(v.type) ?? "totp", secret: v.info?.secret, issuer: v.issuer, account: v.name,
    algorithm: ALG(v.info?.algo), digits: v.info?.digits, period: v.info?.period, counter: v.info?.counter,
  })), "Aegis");
}

/** Detect the format of `text` and import it. */
export async function importAny(text: string, password?: string): Promise<ImportResult> {
  const trimmed = text.trim();
  let json: unknown;
  try { json = JSON.parse(trimmed); } catch { return fromLines(trimmed); }

  if (looksLikeEnvelope(json) && !isEnvelope(json)) {
    throw new Error("This backup has invalid or unsafe encryption settings and was not opened");
  }
  if (isEnvelope(json)) {
    if (!password) return { entries: [], failed: 0, needsPassword: true, format: "authora" };
    let data: VaultData;
    try { data = (await open(json, password)) as VaultData; } catch { throw new WrongBackupPasswordError(); }
    return collect(data.entries || [], "authora");
  }
  if (Array.isArray(json)) return fromAndOtp(json);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const o = json as any;
  if (o && (o.services || o.servicesEncrypted)) return from2fas(o);
  if (o && o.db) return fromAegis(o);
  if (o && typeof o === "object") return fromChrome(o, password);
  throw new Error("Unrecognised file format");
}

const fingerprint = (e: Entry) =>
  `${e.type}|${e.secret.replace(/[\s=]/g, "").toUpperCase()}|${e.account.toLowerCase()}`;

/** Split incoming entries into new ones and a count of ones already in `existing`. */
export function dedupe(existing: Entry[], incoming: Entry[]): { added: Entry[]; duplicates: number } {
  const seen = new Set(existing.map(fingerprint));
  const added: Entry[] = [];
  let duplicates = 0;
  for (const e of incoming) {
    const f = fingerprint(e);
    if (seen.has(f)) { duplicates++; continue; }
    seen.add(f);
    added.push(e);
  }
  return { added, duplicates };
}
