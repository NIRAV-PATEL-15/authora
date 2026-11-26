# Changelog

## 0.2.0 — 2026-11-26
- **New: quick-unlock PIN.** Set a 6-digit PIN and unlock Authora by typing it. It unlocks on the 6th digit, with no Enter.
  - It's offered when you create a vault. Existing users see a one-time "New" pop-up, and can set it up any time in ⋯ → Security
    (set up, change, remove).
  - 3 wrong PINs lock the PIN for 1 minute; the master password always works. After 9 wrong PINs in a row the PIN is erased.
  - The command palette and `Ctrl+Alt+2` ask for the PIN too.
  - The PIN only works on this computer (OS keychain). Your vault file and backups still need the master password.
    Changing the master password erases the PIN and asks you to set it again.

## 0.1.3 — 2026-11-25
Security and reliability release, based on an independent security review. Updating is recommended.
- **Fixed data loss with several VS Code windows open:** changes made in one window could be overwritten by
  another, and a password change could be undone. Every change is now a locked read-modify-write against the
  latest vault file. Windows pick up each other's changes, and a window whose password became outdated locks itself.
- **Fixed:** re-importing your own backup could create entries that shared an internal id, so deleting one
  deleted both. Imports now get fresh ids, and existing duplicates are repaired on unlock.
- **Hardened:** a folder's `.vscode/settings.json` can no longer change Authora's security settings
  (auto-lock, clipboard clearing, remember-key, backup folder). They are now user-level only.
- **Hardened:** backup files with extreme or malformed encryption parameters are rejected immediately
  instead of freezing VS Code.
- **Hardened:** locking (manually or by auto-lock) now also requires the password after a window reload,
  even with "Remember on this machine" on.
- **Hardened:** crash-safe saves (fsync, plus a last-good copy that is used automatically if the vault file is damaged).
- **Hardened:** clock sync rejects invalid server times and asks before applying an offset over 5 minutes.
  Exported files are always owner-only, even when overwriting an existing file. Stricter validation of all UI messages and inputs.
- **Hardened:** the release pipeline now builds without credentials and publishes from a separate job.
  GitHub Actions are pinned to exact commits. Dev tooling updated.

## 0.1.2 — 2026-11-25
- Now also published on Open VSX (Cursor, Windsurf, VSCodium, Gitpod).
- Removed the Preview label.

## 0.1.1 — 2026-11-25
- Releases now publish automatically from GitHub Actions through Marketplace trusted publishing.
- README: release instructions for maintainers.

## 0.1.0 — 2026-11-25
First release.
- Password-protected vault (Argon2id + AES-256-GCM). Locks on startup, on demand and when idle.
  Wrong passwords are throttled.
- TOTP, HOTP, Steam Guard, Battle.net and hex secrets; SHA-1/256/512.
- Add accounts from a QR screenshot (paste or drop), from `otpauth://` links, or by hand.
- Import from Chrome Authenticator, Google Authenticator, andOTP, 2FAS, Aegis and Authora backups.
- Encrypted backup export, plus auto-backup to a folder with rotation.
- Click to copy with clipboard auto-clear, pin, drag to reorder, search, edit, show QR.
- `Ctrl+Alt+2` quick copy, insert code into the editor, status bar lock indicator.
- Advisor and clock sync.
