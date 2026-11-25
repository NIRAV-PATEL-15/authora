import { Entry, OtpAlgorithm, newEntry, validateSecret } from "./otp";
import { base32Encode } from "./base32";

const ALGS: Record<string, OtpAlgorithm> = { SHA1: "SHA1", SHA256: "SHA256", SHA512: "SHA512" };

/** Split "Issuer:account" labels. */
export function splitLabel(label: string): { issuer?: string; account: string } {
  const i = label.indexOf(":");
  if (i < 0) return { account: label.trim() };
  return { issuer: label.slice(0, i).trim(), account: label.slice(i + 1).trim() };
}

/** Parse an otpauth:// URI into a validated Entry. Throws on anything unusable. */
export function parseOtpauth(uri: string): Entry {
  const m = /^otpauth:\/\/([a-z]+)\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!m) throw new Error("Not an otpauth:// URI");
  const kind = m[1].toLowerCase();
  if (kind !== "totp" && kind !== "hotp") throw new Error(`Unsupported OTP type "${kind}"`);
  let label = m[2];
  try { label = decodeURIComponent(label); } catch { /* keep raw */ }
  const q = new URLSearchParams(m[3]);
  const get = (k: string) => {
    for (const [key, v] of q) if (key.toLowerCase() === k) return v;
    return undefined;
  };
  const secret = get("secret");
  if (!secret) throw new Error("URI has no secret");
  const { issuer: labelIssuer, account } = splitLabel(label);
  const issuer = get("issuer") ?? labelIssuer ?? "";
  const encoder = (get("encoder") || "").toLowerCase();
  const alg = ALGS[(get("algorithm") || "SHA1").toUpperCase()];
  const e = newEntry({
    type: encoder === "steam" ? "steam" : (kind as "totp" | "hotp"),
    issuer,
    account,
    secret,
    algorithm: alg,
    digits: Number(get("digits")) || undefined,
    period: Number(get("period")) || undefined,
    counter: Number(get("counter")) || 0,
  });
  validateSecret(e);
  return e;
}

/** Build an otpauth:// URI (for export / QR). hex secrets are converted to base32. */
export function toOtpauth(e: Entry): string {
  const counterBased = e.type === "hotp" || e.type === "hhex";
  const secret = e.type === "hex" || e.type === "hhex"
    ? base32Encode(Buffer.from(e.secret.length % 2 ? e.secret + "0" : e.secret, "hex")).replace(/=/g, "")
    : e.secret.replace(/=/g, "").toUpperCase();
  const label = e.issuer ? `${encodeURIComponent(e.issuer)}:${encodeURIComponent(e.account)}` : encodeURIComponent(e.account);
  const p = new URLSearchParams({ secret });
  if (e.issuer) p.set("issuer", e.issuer);
  p.set("algorithm", e.type === "steam" || e.type === "battle" ? "SHA1" : e.algorithm);
  p.set("digits", String(e.type === "battle" ? 8 : e.type === "steam" ? 5 : e.digits));
  if (counterBased) p.set("counter", String(e.counter));
  else p.set("period", String(e.type === "totp" || e.type === "hex" ? e.period : 30));
  if (e.type === "steam") p.set("encoder", "steam");
  return `otpauth://${counterBased ? "hotp" : "totp"}/${label}?${p.toString().replace(/\+/g, "%20")}`;
}
