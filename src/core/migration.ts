import { Entry, newEntry, OtpAlgorithm } from "./otp";
import { base32Encode } from "./base32";
import { splitLabel } from "./uri";

type Field = { no: number; wire: number; value: number | Buffer };

function readVarint(buf: Buffer, pos: number): [number, number] {
  let result = 0;
  let mul = 1;
  for (;;) {
    if (pos >= buf.length) throw new Error("Truncated varint");
    const b = buf[pos++];
    result += (b & 0x7f) * mul;
    if (!(b & 0x80)) return [result, pos];
    mul *= 128;
  }
}

function readFields(buf: Buffer): Field[] {
  const out: Field[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = readVarint(buf, pos);
    pos = p1;
    const no = Math.floor(tag / 8);
    const wire = tag & 7;
    if (wire === 0) {
      const [v, p2] = readVarint(buf, pos);
      out.push({ no, wire, value: v });
      pos = p2;
    } else if (wire === 2) {
      const [len, p2] = readVarint(buf, pos);
      if (p2 + len > buf.length) throw new Error("Truncated field");
      out.push({ no, wire, value: buf.subarray(p2, p2 + len) });
      pos = p2 + len;
    } else if (wire === 1) { pos += 8; }
    else if (wire === 5) { pos += 4; }
    else throw new Error(`Unsupported wire type ${wire}`);
  }
  return out;
}

const ALG: Record<number, OtpAlgorithm> = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };

/** Decode a Google Authenticator `otpauth-migration://offline?data=...` URI. */
export function parseMigration(uri: string): Entry[] {
  const m = /^otpauth-migration:\/\/[^?]*\?(.*)$/i.exec(uri.trim());
  if (!m) throw new Error("Not an otpauth-migration URI");
  const data = new URLSearchParams(m[1]).get("data");
  if (!data) throw new Error("Migration URI has no data");
  const payload = Buffer.from(data.replace(/ /g, "+"), "base64");
  const entries: Entry[] = [];
  for (const f of readFields(payload)) {
    if (f.no !== 1 || !(f.value instanceof Buffer)) continue;
    let secret = Buffer.alloc(0), name = "", issuer = "", alg = 0, digits = 0, type = 2, counter = 0;
    for (const g of readFields(f.value)) {
      if (g.no === 1 && g.value instanceof Buffer) secret = g.value;
      else if (g.no === 2 && g.value instanceof Buffer) name = g.value.toString("utf8");
      else if (g.no === 3 && g.value instanceof Buffer) issuer = g.value.toString("utf8");
      else if (g.no === 4) alg = g.value as number;
      else if (g.no === 5) digits = g.value as number;
      else if (g.no === 6) type = g.value as number;
      else if (g.no === 7) counter = g.value as number;
    }
    if (alg === 4) continue; // MD5 unsupported
    const label = splitLabel(name);
    entries.push(newEntry({
      type: type === 1 ? "hotp" : "totp",
      secret: base32Encode(secret).replace(/=/g, ""),
      issuer: issuer || label.issuer || "",
      account: label.account,
      algorithm: ALG[alg] ?? "SHA1",
      digits: digits === 2 ? 8 : 6,
      counter,
    }));
  }
  return entries;
}
