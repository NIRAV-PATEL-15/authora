import { argon2id } from "hash-wasm";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface KdfParams {
  alg: "argon2id";
  salt: string; // base64
  m: number; // memory KiB
  t: number; // iterations
  p: number; // parallelism
}

export interface Envelope {
  v: 1;
  kdf: KdfParams;
  iv: string; // base64, 12 bytes
  ct: string; // base64, ciphertext || 16-byte GCM tag
}

export class WrongPasswordError extends Error {
  constructor() {
    super("Wrong password or corrupted data");
    this.name = "WrongPasswordError";
  }
}

export type KdfCost = Pick<KdfParams, "m" | "t" | "p">;
export const DEFAULT_KDF: KdfCost = { m: 65536, t: 3, p: 1 };
/** Cheap parameters so unit tests run fast. Never use in production. */
export const FAST_KDF_FOR_TESTS: KdfCost = { m: 1024, t: 1, p: 1 };

export function newKdf(cost: KdfCost = DEFAULT_KDF): KdfParams {
  return { alg: "argon2id", salt: randomBytes(16).toString("base64"), ...cost };
}

export async function deriveKey(password: string, kdf: KdfParams): Promise<Buffer> {
  const out = await argon2id({
    password: password.normalize("NFKC"),
    salt: Buffer.from(kdf.salt, "base64"),
    memorySize: kdf.m,
    iterations: kdf.t,
    parallelism: kdf.p,
    hashLength: 32,
    outputType: "binary",
  });
  return Buffer.from(out);
}

export function sealWithKey(data: unknown, key: Buffer, kdf: KdfParams): Envelope {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(data), "utf8"), c.final(), c.getAuthTag()]);
  return { v: 1, kdf, iv: iv.toString("base64"), ct: ct.toString("base64") };
}

export function openWithKey(env: Envelope, key: Buffer): unknown {
  try {
    const buf = Buffer.from(env.ct, "base64");
    const d = createDecipheriv("aes-256-gcm", key, Buffer.from(env.iv, "base64"));
    d.setAuthTag(buf.subarray(buf.length - 16));
    const pt = Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]);
    return JSON.parse(pt.toString("utf8"));
  } catch {
    throw new WrongPasswordError();
  }
}

export async function seal(data: unknown, password: string, cost: KdfCost = DEFAULT_KDF): Promise<Envelope> {
  const kdf = newKdf(cost);
  return sealWithKey(data, await deriveKey(password, kdf), kdf);
}

export async function open(env: Envelope, password: string): Promise<unknown> {
  return openWithKey(env, await deriveKey(password, env.kdf));
}

export function isEnvelope(x: unknown): x is Envelope {
  const e = x as Envelope;
  return !!e && e.v === 1 && !!e.kdf && e.kdf.alg === "argon2id" && typeof e.iv === "string" && typeof e.ct === "string";
}
