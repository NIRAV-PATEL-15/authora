export type InsightLevel = "danger" | "warning" | "info";
export interface Insight {
  id: "noBackup" | "staleBackup" | "autoLockOff" | "rememberedKey";
  level: InsightLevel;
  title: string;
  description: string;
}

export interface AdvisorInput {
  entryCount: number;
  autoLockMinutes: number;
  lastBackupAt?: number;
  rememberOnThisMachine: boolean;
  ignored: string[];
  now: number;
}

const STALE_MS = 30 * 86_400_000;

export function advise(s: AdvisorInput): Insight[] {
  const out: Insight[] = [];
  if (s.entryCount > 0 && !s.lastBackupAt) {
    out.push({ id: "noBackup", level: "danger", title: "No backup yet",
      description: "If this machine dies you lose every account. Export a backup or set an auto-backup folder." });
  } else if (s.entryCount > 0 && s.lastBackupAt && s.now - s.lastBackupAt > STALE_MS) {
    out.push({ id: "staleBackup", level: "warning", title: "Backup is over 30 days old",
      description: "Accounts added since then are not backed up." });
  }
  if (s.autoLockMinutes <= 0) {
    out.push({ id: "autoLockOff", level: "warning", title: "Auto-lock is off",
      description: "Anyone at your unlocked machine can read your codes. Set authora.autoLockMinutes." });
  }
  if (s.rememberOnThisMachine) {
    out.push({ id: "rememberedKey", level: "info", title: "Vault key is remembered on this machine",
      description: "The vault opens without a password after restart. Turn off authora.rememberOnThisMachine for full protection." });
  }
  return out.filter((i) => !s.ignored.includes(i.id));
}
