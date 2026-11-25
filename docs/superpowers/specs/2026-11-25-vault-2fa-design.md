# Vault 2FA for VS Code — Design

## Intent
Replace a Chrome 2FA extension (a rebrand of the open-source "Authenticator" extension, with
Mixpanel tracking added) with a VS Code extension offering the same features, a modern UI,
and a password-protected vault. No telemetry.

## Goals
- Same OTP coverage: TOTP, HOTP, Steam, Battle.net, hex/hhex; SHA1/256/512 (+GOST if the
  library works in Node); 6–10 digits; custom periods; clock-offset sync.
- Same account management: add (URI, QR image, manual), edit, delete, pin, reorder, search, copy.
- Same import formats: otpauth lines, `otpauth-migration://` (Google Authenticator), Chrome
  Authenticator backup JSON (plain and password-encrypted), andOTP and 2FAS plain JSON, QR images.
- Password-protected vault: always encrypted at rest, locks on start, on demand and on idle.
- Backup: encrypted export file + optional auto-backup to a chosen folder with rotation.
- Advisor: warns about no backup, stale backup, auto-lock off.

## Non-goals / anti-goals
- No Dropbox/Drive/OneDrive OAuth (decided: a synced folder covers it).
- No page autofill (no browser). Replaced by copy and "insert into editor".
- No analytics, no network calls except the optional manual clock sync.
- Failure even if it works: secrets ever written to disk unencrypted, or the key logged.

## Approaches considered
1. **Webview sidebar + extension-host core (chosen).** Crypto and storage in Node; the webview
   only renders and never holds the key. Rich UI, strong isolation.
2. Native TreeView only — no countdown rings, cards, or image paste; too plain for "modern UI".
3. Full Vue app port — heavy bundle and keeps the original's architecture weaknesses.

## Design (approved in chat)
- **Repo:** `~/workspace/extentions/vault-2fa`, TypeScript, esbuild, two bundles
  (extension host + webview), vitest for core tests.
- **Vault file:** `globalStorage/vault.json` =
  `{v:1, kdf:{alg:"argon2id", salt, m:65536, t:3, p:1}, iv, ct}`. Master password →
  Argon2id (hash-wasm) → 256-bit key → AES-256-GCM over the JSON of all entries. GCM tag
  failure = wrong password. Writes are atomic (temp file + rename).
- **Password is mandatory** (my call): first run shows a "create vault" screen.
- **Session:** key in extension-host memory only. Lock clears it and the decrypted entries.
  Auto-lock after `vault2fa.autoLockMinutes` (default 15) of no interaction. Optional
  `vault2fa.rememberOnThisMachine` stores the key in VS Code SecretStorage (OS keychain).
  Wrong-password attempts back off exponentially (my call).
- **UI:** Activity Bar view with cards: letter avatar (deterministic colour), issuer, account,
  big monospace code, countdown ring; search, pin, drag reorder, edit sheet, menu, lock button,
  follows VS Code theme. Status bar 🔒/🔓 item. Command palette: Unlock, Lock, Copy Code (quick
  pick), Add from URI, Import, Export Backup, Sync Clock.
- **Copy:** clipboard auto-clears after `vault2fa.clipboardClearSeconds` (default 30; my call).
- **QR:** decoded in the webview (canvas + jsQR) from a pasted or chosen image; only the decoded
  text is sent to the host.
- **Backup:** `.vault2fa` file = same envelope as the vault, with its own password. Auto-backup
  folder writes after every change, keeps last `vault2fa.backupKeep` (default 10) files.
- **Clock sync:** reads the `Date` header from `https://www.google.com` (as the original did),
  stored as an offset.

## Left to the builder
Exact visual styling, file layout inside `src/`, GOST inclusion depending on library support.
