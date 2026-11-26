// Messages between the extension host and the webview. Secrets never appear here.
import type { OtpType, OtpAlgorithm } from "../core/otp";
import type { Insight } from "../core/advisor";

export interface EntryView {
  id: string;
  type: OtpType;
  issuer: string;
  account: string;
  period: number;
  digits: number;
  algorithm: OtpAlgorithm;
  pinned: boolean;
  counterBased: boolean;
  code: string; // "" when the secret is invalid
}

export interface ViewSettings {
  hideCodes: boolean;
  autoLockMinutes: number;
  rememberOnThisMachine: boolean;
  autoBackupFolder: string;
  pinSet: boolean;
}

/** Shown on the locked screen when a quick-unlock PIN is stored on this machine. */
export interface PinView {
  lockedMs: number;
  failures: number;
}

export type ViewState =
  | { screen: "setup" }
  | { screen: "locked"; throttledMs?: number; remember: boolean; pin?: PinView }
  | {
      screen: "unlocked";
      entries: EntryView[];
      offset: number;
      insights: Insight[];
      settings: ViewSettings;
      lastBackupAt?: number;
      /** Offer to set a PIN: right after creating a vault, or once as a "new feature" for existing users. */
      offerPin?: "afterCreate" | "newFeature";
    };

export type HostMsg =
  | { type: "state"; state: ViewState }
  | { type: "codes"; codes: Record<string, string> }
  | { type: "toast"; text: string; kind?: "ok" | "error" }
  | { type: "error"; form: string; text: string }
  | { type: "done"; form: string }
  | { type: "qr"; id: string; svg: string; label: string }
  | { type: "needPassword"; form: "import"; text: string; format: string }
  | { type: "pinAgain" };

export interface ManualEntry {
  issuer: string;
  account: string;
  secret: string;
  type: OtpType;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
}

export type ViewMsg =
  | { type: "ready" }
  | { type: "activity" }
  | { type: "create"; password: string }
  | { type: "unlock"; password: string; remember: boolean }
  | { type: "unlockPin"; pin: string; remember: boolean }
  | { type: "setPin"; pin: string }
  | { type: "removePin" }
  | { type: "dismissPinOffer" }
  | { type: "lock" }
  | { type: "refresh" }
  | { type: "copy"; id: string }
  | { type: "next"; id: string }
  | { type: "addManual"; entry: ManualEntry }
  | { type: "importText"; text: string; password?: string }
  | { type: "importFile" }
  | { type: "update"; id: string; patch: { issuer: string; account: string } }
  | { type: "delete"; id: string }
  | { type: "pin"; id: string }
  | { type: "reorder"; ids: string[] }
  | { type: "showQr"; id: string }
  | { type: "exportEncrypted"; password: string }
  | { type: "exportPlain" }
  | { type: "backupNow" }
  | { type: "chooseBackupFolder" }
  | { type: "changePassword"; oldPassword: string; newPassword: string }
  | { type: "syncClock" }
  | { type: "ignoreInsight"; id: string }
  | { type: "setSetting"; key: "hideCodes" | "autoLockMinutes" | "rememberOnThisMachine"; value: boolean | number };
