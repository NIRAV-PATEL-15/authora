// PIN rules shared by the extension host and the webview (no Node imports here).

export const PIN_LENGTH = 6;

export const PIN_INFO_TEXT =
  "3 wrong PINs lock the PIN for 1 minute. After 9 wrong PINs in a row, the PIN is erased and you'll need your master password.";

export function isPinFormat(s: unknown): s is string {
  return typeof s === "string" && /^\d{6}$/.test(s);
}

/** All-same digits, straight runs up or down, and ababab / abcabc / aabbcc patterns. */
export function isWeakPin(pin: string): boolean {
  const d = [...pin].map(Number);
  const steps = d.slice(1).map((x, i) => x - d[i]);
  if (steps.every((s) => s === 0)) return true;
  if (steps.every((s) => s === 1) || steps.every((s) => s === -1)) return true;
  if (pin === pin.slice(0, 2).repeat(3)) return true;
  if (pin === pin.slice(0, 3).repeat(2)) return true;
  if (pin[0] === pin[1] && pin[2] === pin[3] && pin[4] === pin[5]) return true;
  return false;
}
