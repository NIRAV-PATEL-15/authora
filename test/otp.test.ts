import { describe, it, expect } from "vitest";
import { generateCode, remainingSeconds, newEntry } from "../src/core/otp";
import { base32Decode, base32Encode } from "../src/core/base32";

// RFC 6238 seeds (ASCII) encoded as base32
const seed20 = base32Encode(Buffer.from("12345678901234567890"));
const seed32 = base32Encode(Buffer.from("12345678901234567890123456789012"));
const seed64 = base32Encode(
  Buffer.from("1234567890123456789012345678901234567890123456789012345678901234")
);

describe("base32", () => {
  it("round-trips and tolerates spaces, lowercase, missing padding", () => {
    const b = Buffer.from("Hello!\xde\xad\xbe\xef", "latin1");
    const enc = base32Encode(b);
    expect(base32Decode(enc)).toEqual(b);
    expect(base32Decode(enc.toLowerCase().replace(/=/g, ""))).toEqual(b);
    expect(base32Decode("jbsw y3dp ehpk 3pxp")).toEqual(Buffer.from("Hello!\xde\xad\xbe\xef", "latin1"));
  });
  it("rejects invalid chars", () => {
    expect(() => base32Decode("ABC1")).toThrow();
  });
});

describe("TOTP RFC 6238", () => {
  const t = 59_000;
  it("SHA1", () => {
    expect(generateCode(newEntry({ secret: seed20, digits: 8 }), t, 0)).toBe("94287082");
  });
  it("SHA256", () => {
    expect(generateCode(newEntry({ secret: seed32, digits: 8, algorithm: "SHA256" }), t, 0)).toBe("46119246");
  });
  it("SHA512", () => {
    expect(generateCode(newEntry({ secret: seed64, digits: 8, algorithm: "SHA512" }), t, 0)).toBe("90693936");
  });
  it("applies clock offset", () => {
    expect(generateCode(newEntry({ secret: seed20, digits: 8 }), 1111111109_000 - 1_050_000, 1_050)).toBe("07081804");
  });
  it("remainingSeconds", () => {
    expect(remainingSeconds(30, 59_000, 0)).toBe(1);
    expect(remainingSeconds(30, 60_000, 0)).toBe(30);
  });
});

describe("HOTP RFC 4226", () => {
  it("counter 0..2", () => {
    const e = newEntry({ type: "hotp", secret: seed20 });
    expect([0, 1, 2].map((c) => generateCode({ ...e, counter: c }, 0, 0))).toEqual([
      "755224",
      "287082",
      "359152",
    ]);
  });
  it("hex secret (hhex)", () => {
    const e = newEntry({ type: "hhex", secret: Buffer.from("12345678901234567890").toString("hex") });
    expect(generateCode(e, 0, 0)).toBe("755224");
  });
});

describe("special types", () => {
  it("steam is 5 chars from steam alphabet", () => {
    const c = generateCode(newEntry({ type: "steam", secret: seed20 }), 59_000, 0);
    expect(c).toMatch(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
  });
  it("battle is 8 digits", () => {
    expect(generateCode(newEntry({ type: "battle", secret: seed20 }), 59_000, 0)).toBe("94287082");
  });
});
