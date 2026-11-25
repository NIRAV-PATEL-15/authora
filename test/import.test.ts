import { describe, it, expect } from "vitest";
import * as CryptoJS from "crypto-js";
import { parseOtpauth, toOtpauth } from "../src/core/uri";
import { parseMigration } from "../src/core/migration";
import { importAny, dedupe } from "../src/core/importers";
import { seal, FAST_KDF_FOR_TESTS } from "../src/core/envelope";
import { newEntry } from "../src/core/otp";
import { base32Encode } from "../src/core/base32";

describe("otpauth URI", () => {
  it("parses full URI", () => {
    const e = parseOtpauth(
      "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
    );
    expect(e).toMatchObject({
      type: "totp", issuer: "ACME Co", account: "john.doe@email.com",
      secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", algorithm: "SHA256", digits: 8, period: 60,
    });
  });
  it("issuer only in label, with space after colon", () => {
    expect(parseOtpauth("otpauth://totp/GitHub:%20me?secret=JBSWY3DPEHPK3PXP")).toMatchObject({
      issuer: "GitHub", account: "me",
    });
  });
  it("hotp counter and steam encoder", () => {
    expect(parseOtpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=5")).toMatchObject({ type: "hotp", counter: 5 });
    expect(parseOtpauth("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam").type).toBe("steam");
  });
  it("rejects missing or bad secret", () => {
    expect(() => parseOtpauth("otpauth://totp/x?issuer=a")).toThrow();
    expect(() => parseOtpauth("otpauth://totp/x?secret=!!!")).toThrow();
    expect(() => parseOtpauth("https://example.com")).toThrow();
  });
  it("round trips through toOtpauth", () => {
    const e = newEntry({ issuer: "A B", account: "c:d", secret: "JBSWY3DPEHPK3PXP", digits: 8, algorithm: "SHA512" });
    expect(parseOtpauth(toOtpauth(e))).toMatchObject({ issuer: "A B", account: "c:d", digits: 8, algorithm: "SHA512" });
  });
});

// --- tiny protobuf encoder to build a Google Authenticator migration payload
function varint(n: number): number[] {
  const out: number[] = [];
  while (n > 127) { out.push((n & 127) | 128); n >>>= 7; }
  out.push(n);
  return out;
}
const field = (no: number, wire: number) => varint((no << 3) | wire);
const bytes = (no: number, b: number[]) => [...field(no, 2), ...varint(b.length), ...b];
const str = (no: number, s: string) => bytes(no, [...Buffer.from(s)]);
const num = (no: number, n: number) => [...field(no, 0), ...varint(n)];

describe("Google Authenticator migration", () => {
  it("decodes multiple entries incl. long names and hotp", () => {
    const longName = "x".repeat(200) + "@example.com";
    const p1 = [...bytes(1, [...Buffer.from("12345678901234567890")]), ...str(2, "Google:" + longName), ...str(3, "Google"), ...num(4, 2), ...num(5, 2), ...num(6, 2)];
    const p2 = [...bytes(1, [1, 2, 3, 4, 5]), ...str(2, "bob"), ...num(6, 1), ...num(7, 42)];
    const payload = Buffer.from([...bytes(1, p1), ...bytes(1, p2), ...num(2, 1)]);
    const uri = "otpauth-migration://offline?data=" + encodeURIComponent(payload.toString("base64"));
    const [a, b] = parseMigration(uri);
    expect(a).toMatchObject({ type: "totp", issuer: "Google", account: longName, algorithm: "SHA256", digits: 8,
      secret: base32Encode(Buffer.from("12345678901234567890")).replace(/=/g, "") });
    expect(b).toMatchObject({ type: "hotp", account: "bob", counter: 42, digits: 6, algorithm: "SHA1" });
  });
});

describe("importAny", () => {
  it("otpauth lines, skipping junk and counting failures", async () => {
    const r = await importAny("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP\n\nhello\notpauth://totp/B?secret=@@@\n");
    expect(r.entries.map((e) => e.account)).toEqual(["A"]);
    expect(r.failed).toBe(1);
  });

  it("Chrome Authenticator plain backup with blz-/stm- prefixes", async () => {
    const json = JSON.stringify({
      h1: { account: "me", issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP", type: "totp", encrypted: false, hash: "h1", index: 0 },
      h2: { account: "b", secret: "blz-JBSWY3DPEHPK3PXP", encrypted: false },
      h3: { account: "s", secret: "stm-JBSWY3DPEHPK3PXP", encrypted: false },
    });
    const r = await importAny(json);
    expect(r.entries.map((e) => [e.account, e.type])).toEqual([["me", "totp"], ["b", "battle"], ["s", "steam"]]);
  });

  it("Chrome Authenticator key-encrypted backup", async () => {
    const wordArray = CryptoJS.lib.WordArray.random(120);
    const enc = CryptoJS.AES.encrypt(wordArray, "pw").toString();
    const secret = CryptoJS.AES.encrypt("JBSWY3DPEHPK3PXP", wordArray.toString()).toString();
    const json = JSON.stringify({ key: { enc, hash: "x" }, u1: { account: "me", secret, encrypted: true } });
    const locked = await importAny(json);
    expect(locked.needsPassword).toBe(true);
    const r = await importAny(json, "pw");
    expect(r.entries[0].secret).toBe("JBSWY3DPEHPK3PXP");
    await expect(importAny(json, "bad")).rejects.toThrow(/password/i);
  });

  it("Chrome legacy password-encrypted backup", async () => {
    const secret = CryptoJS.AES.encrypt("JBSWY3DPEHPK3PXP", "pw").toString();
    const r = await importAny(JSON.stringify({ u1: { account: "me", secret, encrypted: true } }), "pw");
    expect(r.entries[0].secret).toBe("JBSWY3DPEHPK3PXP");
  });

  it("andOTP, 2FAS, Aegis", async () => {
    const andotp = JSON.stringify([{ secret: "JBSWY3DPEHPK3PXP", issuer: "X", label: "X:me", digits: 6, type: "TOTP", algorithm: "SHA1", period: 30 }]);
    expect((await importAny(andotp)).entries[0]).toMatchObject({ issuer: "X", account: "me" });
    const twofas = JSON.stringify({ services: [{ secret: "JBSWY3DPEHPK3PXP", name: "Y", otp: { account: "me", digits: 8, period: 30, algorithm: "SHA256", tokenType: "TOTP" } }] });
    expect((await importAny(twofas)).entries[0]).toMatchObject({ issuer: "Y", account: "me", digits: 8, algorithm: "SHA256" });
    const aegis = JSON.stringify({ db: { entries: [{ type: "steam", name: "me", issuer: "Steam", info: { secret: "JBSWY3DPEHPK3PXP", algo: "SHA1", digits: 5, period: 30 } }] } });
    expect((await importAny(aegis)).entries[0]).toMatchObject({ type: "steam", issuer: "Steam" });
  });

  it("own .authora backup", async () => {
    const env = await seal({ entries: [newEntry({ issuer: "Z", secret: "JBSWY3DPEHPK3PXP" })] }, "bpw", FAST_KDF_FOR_TESTS);
    expect((await importAny(JSON.stringify(env))).needsPassword).toBe(true);
    expect((await importAny(JSON.stringify(env), "bpw")).entries[0].issuer).toBe("Z");
  });
});

describe("dedupe", () => {
  it("skips same secret+account", () => {
    const a = newEntry({ account: "me", secret: "JBSWY3DPEHPK3PXP" });
    const r = dedupe([a], [newEntry({ account: "me", secret: "jbsw y3dp ehpk 3pxp" }), newEntry({ account: "you", secret: "JBSWY3DPEHPK3PXP" })]);
    expect(r.added.map((e) => e.account)).toEqual(["you"]);
    expect(r.duplicates).toBe(1);
  });
});
