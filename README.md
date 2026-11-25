# Vault 2FA

A password-protected two-factor authenticator for VS Code. It works like the Chrome "Authenticator"
extension, but lives in your editor's sidebar and has no telemetry.

## Features
- **Codes:** TOTP, HOTP, Steam Guard, Battle.net and hex secrets; SHA-1/256/512; 1–10 digits; custom periods.
- **Encrypted vault:** your master password goes through Argon2id (64 MiB, 3 passes) to make an
  AES-256-GCM key. Nothing is ever stored in plain text.
- **Locking:** the vault locks when VS Code starts, when you click lock, and after inactivity.
  Wrong passwords are throttled.
- **Remember on this machine (optional):** keeps the key in the OS keychain through VS Code SecretStorage.
- **Adding accounts:** paste or drop a QR screenshot, paste `otpauth://` links (including Google
  Authenticator export links), or type the details by hand.
- **Import:** Chrome Authenticator backups (plain and password-encrypted), Google Authenticator,
  andOTP, 2FAS, Aegis (unencrypted) and Vault 2FA backups.
- **Backup:** encrypted export file, plus auto-backup to a folder after every change. Point it at a
  Dropbox/Drive/OneDrive folder for cloud sync.
- **Account management:** click a card to copy its code (the clipboard clears automatically), pin,
  drag to reorder, search, edit, show QR, delete.
- **Commands:** `Ctrl+Alt+2` copies a code from anywhere, "Insert Code into Editor" types one in,
  and the status bar shows the lock state.
- **Advisor:** warns when you have no backup or a stale one, or auto-lock is off.
- **Clock sync:** corrects for a wrong system clock.

## Develop
```bash
npm install
npm test          # core unit tests
npm run build     # bundles dist/extension.js + dist/webview.js
npm run package   # builds vault-2fa-<version>.vsix
code --install-extension vault-2fa-0.1.0.vsix
```
Press F5 in this folder to launch an Extension Development Host.

## Where data lives
`~/.config/Code/User/globalStorage/local.vault-2fa/vault.json` (Linux) holds the encrypted envelope
`{v, kdf:{argon2id, salt, m, t, p}, iv, ct}`. Without the password it is useless.
There is **no password recovery**, so keep a backup.
