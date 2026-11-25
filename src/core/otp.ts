import { createHmac, randomUUID } from "node:crypto";
import { base32Decode } from "./base32";

export type OtpType = "totp" | "hotp" | "battle" | "steam" | "hex" | "hhex";
export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface Entry {
  id: string;
  type: OtpType;
  issuer: string;
  account: string;
  secret: string;
  period: number;
  digits: number;
  algorithm: OtpAlgorithm;
  counter: number;
  pinned: boolean;
}

export const OTP_TYPES: OtpType[] = ["totp", "hotp", "battle", "steam", "hex", "hhex"];
export const ALGORITHMS: OtpAlgorithm[] = ["SHA1", "SHA256", "SHA512"];
const STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY";

export function isCounterBased(type: OtpType): boolean {
  return type === "hotp" || type === "hhex";
}

/** Fill defaults and normalise a partial entry. */
export function newEntry(p: Partial<Entry>): Entry {
  const type = p.type && OTP_TYPES.includes(p.type) ? p.type : "totp";
  const algorithm = p.algorithm && ALGORITHMS.includes(p.algorithm) ? p.algorithm : "SHA1";
  const digits = p.digits && p.digits >= 1 && p.digits <= 10 ? Math.floor(p.digits) : 6;
  const period = p.period && p.period > 0 ? Math.floor(p.period) : 30;
  return {
    id: p.id || randomUUID(),
    type,
    issuer: (p.issuer || "").trim(),
    account: (p.account || "").trim(),
    secret: (p.secret || "").replace(/\s/g, ""),
    period,
    digits,
    algorithm,
    counter: p.counter && p.counter > 0 ? Math.floor(p.counter) : 0,
    pinned: !!p.pinned,
  };
}

function keyBytes(e: Entry): Buffer {
  if (e.type === "hex" || e.type === "hhex") {
    let hex = e.secret.replace(/\s/g, "");
    if (!/^[0-9a-f]*$/i.test(hex) || !hex) throw new Error("Invalid hex secret");
    if (hex.length % 2) hex += "0";
    return Buffer.from(hex, "hex");
  }
  const key = base32Decode(e.secret);
  if (!key.length) throw new Error("Empty secret");
  return key;
}

/** Throws if the secret cannot produce a code. */
export function validateSecret(e: Entry): void {
  keyBytes(e);
}

export function remainingSeconds(period: number, nowMs: number, offsetSec: number): number {
  const epoch = Math.floor(nowMs / 1000) + offsetSec;
  return period - (epoch % period);
}

export function generateCode(e: Entry, nowMs: number, offsetSec: number): string {
  const key = keyBytes(e);
  let counter: number;
  if (isCounterBased(e.type)) {
    counter = e.counter;
  } else {
    const period = e.type === "totp" || e.type === "hex" ? e.period : 30;
    counter = Math.floor((Math.floor(nowMs / 1000) + offsetSec) / period);
  }
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const alg = e.type === "totp" || e.type === "hotp" || e.type === "hex" || e.type === "hhex" ? e.algorithm : "SHA1";
  const hmac = createHmac(alg.toLowerCase(), key).update(msg).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  let bin = hmac.readUInt32BE(off) & 0x7fffffff;

  if (e.type === "steam") {
    let out = "";
    for (let i = 0; i < 5; i++) {
      out += STEAM_CHARS[bin % STEAM_CHARS.length];
      bin = Math.floor(bin / STEAM_CHARS.length);
    }
    return out;
  }
  const digits = e.type === "battle" ? 8 : e.digits;
  return String(bin).padStart(10, "0").slice(-digits);
}
