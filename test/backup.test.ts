import { describe, it, expect } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { writeBackup, backupFileName } from "../src/core/backup";
import { advise } from "../src/core/advisor";
import { importAny } from "../src/core/importers";
import { newEntry } from "../src/core/otp";
import { FAST_KDF_FOR_TESTS } from "../src/core/envelope";

const DAY = 86_400_000;

describe("backup", () => {
  it("names files by timestamp", () => {
    expect(backupFileName(new Date(2026, 10, 25, 9, 5, 7))).toBe("vault2fa-20261125-090507.vault2fa");
  });
  it("writes an importable encrypted file and keeps only N newest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "v2fa-b-"));
    writeFileSync(join(dir, "unrelated.txt"), "x");
    for (let i = 0; i < 4; i++) {
      await writeBackup(dir, [newEntry({ issuer: "I" + i, secret: "JBSWY3DPEHPK3PXP" })], "pw", 2, new Date(2026, 0, 1, 0, 0, i), FAST_KDF_FOR_TESTS);
    }
    const files = readdirSync(dir).sort();
    expect(files).toEqual(["unrelated.txt", "vault2fa-20260101-000002.vault2fa", "vault2fa-20260101-000003.vault2fa"]);
    const r = await importAny(readFileSync(join(dir, files[2]), "utf8"), "pw");
    expect(r.entries[0].issuer).toBe("I3");
  });
});

describe("advisor", () => {
  const now = 100 * DAY;
  const base = { entryCount: 3, autoLockMinutes: 15, now, lastBackupAt: now - DAY, rememberOnThisMachine: false, ignored: [] as string[] };
  it("is quiet when all is well", () => {
    expect(advise(base)).toEqual([]);
  });
  it("flags no backup, stale backup, autolock off, remembered key", () => {
    expect(advise({ ...base, lastBackupAt: undefined }).map((i) => i.id)).toEqual(["noBackup"]);
    expect(advise({ ...base, lastBackupAt: now - 31 * DAY }).map((i) => i.id)).toEqual(["staleBackup"]);
    expect(advise({ ...base, autoLockMinutes: 0 }).map((i) => i.id)).toEqual(["autoLockOff"]);
    expect(advise({ ...base, rememberOnThisMachine: true }).map((i) => i.id)).toEqual(["rememberedKey"]);
  });
  it("no backup warning when vault empty, respects ignore list", () => {
    expect(advise({ ...base, entryCount: 0, lastBackupAt: undefined })).toEqual([]);
    expect(advise({ ...base, autoLockMinutes: 0, ignored: ["autoLockOff"] })).toEqual([]);
  });
});
