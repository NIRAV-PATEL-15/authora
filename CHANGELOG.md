# Changelog

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
