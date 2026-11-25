import type { ViewMsg } from "./protocol";

const str = (v: unknown, max = 512) => typeof v === "string" && v.length <= max;
const bool = (v: unknown) => typeof v === "boolean";
const int = (v: unknown, lo: number, hi: number) => Number.isInteger(v) && (v as number) >= lo && (v as number) <= hi;
const TYPES = ["totp", "hotp", "battle", "steam", "hex", "hhex"];
const ALGS = ["SHA1", "SHA256", "SHA512"];
/** Upper bound on pasted import text (a few thousand accounts is far beyond real use). */
export const MAX_IMPORT_CHARS = 2_000_000;

/** Defence in depth: the webview is ours, but never trust message shapes blindly. */
export function isValidViewMsg(x: unknown): x is ViewMsg {
  if (!x || typeof x !== "object") return false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const m = x as any;
  switch (m.type) {
    case "ready": case "activity": case "lock": case "refresh": case "importFile": case "exportPlain":
    case "backupNow": case "chooseBackupFolder": case "syncClock":
      return true;
    case "create": return str(m.password, 1024);
    case "unlock": return str(m.password, 1024) && bool(m.remember);
    case "copy": case "next": case "delete": case "pin": case "showQr": return str(m.id, 64);
    case "ignoreInsight": return str(m.id, 64);
    case "importText": return str(m.text, MAX_IMPORT_CHARS) && (m.password === undefined || str(m.password, 1024));
    case "update": return str(m.id, 64) && !!m.patch && str(m.patch.issuer, 128) && str(m.patch.account, 256);
    case "reorder": return Array.isArray(m.ids) && m.ids.length <= 10_000 && m.ids.every((i: unknown) => str(i, 64));
    case "exportEncrypted": return str(m.password, 1024);
    case "changePassword": return str(m.oldPassword, 1024) && str(m.newPassword, 1024);
    case "addManual": {
      const e = m.entry;
      return !!e && str(e.issuer, 128) && str(e.account, 256) && str(e.secret, 1024) && TYPES.includes(e.type)
        && ALGS.includes(e.algorithm) && int(e.digits, 1, 10) && int(e.period, 1, 86_400) && int(e.counter, 0, Number.MAX_SAFE_INTEGER);
    }
    case "setSetting":
      return (m.key === "hideCodes" || m.key === "rememberOnThisMachine") ? bool(m.value)
        : m.key === "autoLockMinutes" ? int(m.value, 0, 1440) : false;
    default: return false;
  }
}
