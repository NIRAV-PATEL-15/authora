# PIN Quick Unlock: Design

## Intent
Typing a long master password many times a day is slow. Users can add a **6-digit PIN** that becomes the
**main way to unlock** Authora on this machine. It unlocks **automatically on the 6th digit**, with no Enter key
or button. The master password always remains. It protects the vault file and backups, and it is the fallback
when the PIN is locked out or erased.

## Goals
- After creating the vault (master password, as today), offer **"Set a 6-digit PIN for quick unlock"** right away,
  with a **Skip** option.
- When a PIN is set, every unlock prompt shows the PIN first: the sidebar locked screen, `Authora: Unlock Vault`,
  `Ctrl+Alt+2` and every command that goes through `ensureUnlocked`. The master password is always one click away
  through **"Use master password"**.
- Six separate boxes, as in the approved mockup. Entry auto-advances, Backspace steps back, pasting fills all six,
  and the PIN submits automatically on the 6th digit.
- **Wrong-PIN rules:**
  - 3 wrong PINs lock PIN entry for **1 minute**. The master password still works during that minute.
  - After **3 lockouts in a row (9 wrong PINs)** the PIN is **erased**, and the master password is required.
    The user can then set a new PIN.
- An **(i) info icon** on PIN screens explains these rules: *"3 wrong PINs lock the PIN for 1 minute. After 9 wrong
  PINs in a row, the PIN is erased and you'll need your master password."*
- Settings (Security sheet): **Set up PIN**, **Change PIN**, **Remove PIN**.
- **One-time "New feature" pop-up for existing users.** The first time an existing user unlocks after updating, the sidebar
  shows a pop-up sheet:
  - title **"New: quick-unlock PIN"**, the (i) rules, and two buttons, **Set up PIN** and **Not now**;
  - **Set up PIN** goes straight into the six-box PIN setup;
  - **Not now** closes it for good, and the PIN stays available in Settings → Security.
- **One rule covers both cases.** `globalState` key `authora.pinOfferShown` drives the pop-up. The unlocked `ViewState` carries
  `offerPin: true` while the vault is unlocked, no PIN is set, and the flag is unset.
  - A brand-new vault gets the same offer (as the "Set a quick-unlock PIN" screen with **Skip**).
  - An upgraded vault gets the "New" pop-up.
  - Either choice sends `{ type: "dismissPinOffer" }`, which sets the flag. Setting a PIN also sets it.
  - If the user unlocks from the command palette, the pop-up waits until the sidebar is next shown. No VS Code notification is used *(our call)*.

## Non-goals
- A PIN-only vault with no master password. This was considered (option A) and rejected.
- PIN on other machines. The PIN lives in this machine's OS keychain and is not synced.
- Changes to the vault file format, encrypted export, auto-backup, or "Remember on this machine".

## Anti-goals (failure even if it works)
- The vault file or any backup becoming openable with the PIN. These must still need the master password.
- The PIN, the derived key, or the vault key written anywhere unencrypted, logged, or sent to the webview.
- A wrong-PIN count that resets on window reload, so guessing could continue forever.
- A user locked out of a vault they know the master password for.

## Approaches considered
- **A. PIN replaces the password.** Simple, but a stolen vault file or backup becomes crackable (only 10⁶ PINs), and
  there is no password to fall back to after wrong PINs. Rejected.
- **B. PIN as quick unlock over the master password, with the vault key wrapped in the OS keychain (chosen).** The file
  and backups stay as strong as the password. The PIN only works on this machine, and the attempt limit bounds online guessing.
- **B′. Store the PIN-wrapped key inside `vault.json` as a second "key slot".** This would carry the PIN across machines, but it
  makes the file offline-crackable through the PIN, which is the same weakness as A. Rejected.

## Design decisions

### Storage
- The new SecretStorage entry **`authora.pin`** holds JSON `{ vaultSalt, env }`, where:
  - `env` is a standard `Envelope` (`seal` from `src/core/envelope.ts`, Argon2id `DEFAULT_KDF`, AES-256-GCM)
    whose plaintext is the vault key as base64;
  - `vaultSalt` is the vault's current `kdf.salt`. It is used to detect that the vault was re-keyed.
- `globalState` keys hold the attempt state so it survives reloads and is shared by windows:
  - `authora.pinFailures` (integer)
  - `authora.pinLockedUntil` (epoch ms)
- A small core module (e.g. `src/core/pin.ts`) holds the pure logic, with no `vscode` import, so it can be unit-tested:
  - wrap and unwrap the key
  - the PIN format check (`/^\d{6}$/`) and weak-PIN check
  - the attempt state machine
- `Session` does the storage I/O.

### Unlock with PIN (`Session.unlockWithPin(pin)`)
1. If `now < pinLockedUntil`, throw a throttled error with the remaining ms.
2. If no PIN is stored, or `vaultSalt` ≠ the vault file's current `kdf.salt` (another window or machine changed the
   password), erase the PIN and throw "PIN no longer valid, use your master password".
3. Unwrap. On success: `store.unlockWithKey(key)`, reset failures and lock-until, clear `requirePassword` (same as a
   password unlock), `touch`, fire.
4. On a wrong PIN, increment `pinFailures`:
   - at 3 or 6 failures, set `pinLockedUntil = now + 60 s`;
   - at 9 failures, erase the PIN, reset the counters, and tell the user "Too many wrong PINs. PIN erased. Unlock
     with your master password."
5. A successful **master-password** unlock also resets the PIN counters, but does not restore an erased PIN.
- The PIN keeps working after manual lock and auto-lock. `requirePassword` only blocks the *remembered key*
  auto-unlock, and it does not block the PIN.

### Setting, changing and removing the PIN (vault must be unlocked)
- **Set / Change:** enter a new PIN, then confirm it in the six boxes. It saves automatically when they match. A weak PIN
  is rejected with "Too easy to guess": all digits the same, ascending or descending runs (`123456`, `654321`, `012345`),
  and repeated pairs or triples (`121212`, `123123`, `112233`). Saving wraps the current in-memory key and resets the counters.
  No password re-entry is needed while unlocked *(our call, matching "Remember on this machine")*.
- **Remove:** a confirm dialog, then erase.
- **Master password change:** erase the PIN. Only if a PIN existed before the change, ask for it again *(our call)*:
  - in the sidebar, by opening the "Set your PIN again" sheet, which can be skipped;
  - from the command palette, with two input boxes (PIN, then confirm), where Escape skips.
- **Stale key:** if the PIN decrypts but the vault won't open with the key it holds, the PIN is out of date. Erase it
  and don't count it as a wrong PIN.
- **Implementation calls:**
  - `viewState()` is synchronous, so `Session` caches whether a PIN is stored.
  - Updates to the attempt counter happen under the existing vault lock file, so two windows guessing at once can't lose updates.
  - After 6 failures, the warning says the next failures erase the PIN, not that they cause another 1-minute lock.

### Protocol (`src/shared/protocol.ts`, `validate.ts`)
- `ViewState.locked` gains `pin?: { lockedMs?: number; failures: number }`. It is present only when a PIN is stored and valid.
- `ViewState.unlocked.settings` gains `pinSet: boolean`.
- New `ViewMsg`s:
  - `{ type: "unlockPin"; pin; remember }`
  - `{ type: "setPin"; pin }`
  - `{ type: "removePin" }`
- The validator checks `pin` against `/^\d{6}$/`. The host re-checks the format and weak-PIN rule.

### Screens (webview)
- **Shared six-box component:** 36×44 boxes, masked digits, existing input and focus colours, a shake on error,
  disabled while submitting or locked.
- **Locked screen, PIN available (default):**
  - lock orb, "Vault locked", "Enter your PIN", **(i)** icon, six boxes focused, "Remember on this machine",
    and a **"Use master password"** link;
  - a wrong PIN shows "Wrong PIN · N tries before a 1-minute lock" and clears and refocuses the boxes;
  - when locked out, the boxes are disabled with a live "PIN locked · try again in 0:42" and the link is highlighted;
  - when the PIN is erased, the screen switches to the password screen with that message.
- **Locked screen, password:** today's screen, plus a **"Use PIN"** link when a PIN is available.
- **PIN setup sheet:**
  - "Set a 6-digit PIN" with **(i)**, then "Confirm your PIN". It saves automatically on a match.
  - After first vault creation it shows a **Skip** link. Opened from Settings it has the normal back arrow.
- **Security sheet:** a row reading "Quick-unlock PIN: On / Off". Its buttons are **Set up** when the PIN is off,
  and **Change** and **Remove** when it is on.

### Command palette (`extension.ts` → `ensureUnlocked`)
- If a PIN is available and not locked out, use `vscode.window.createInputBox` with `password: true`:
  - the title reads "Authora PIN";
  - a title-bar button, **"Use master password"**, switches to the password prompt;
  - it accepts automatically when the value matches `/^\d{6}$/`;
  - a wrong PIN shows `validationMessage` and clears the box;
  - lockout or erasure closes the box and falls through to the password prompt with an explanatory message.
- Otherwise, the existing password prompt.

## Left to the builder
- Module and function names, and the structure of the webview component and its CSS.
- Exact weak-PIN detection code (it must cover the classes above).
- Behaviour when SecretStorage is unavailable or throws: treat it as "no PIN" and never block the password path.
- Tests, at minimum:
  - core wrap/unwrap round trip, and a wrong PIN rejected
  - the state machine: 3 → 60 s lock, 6 → lock, 9 → erase; success resets; password unlock resets
  - a stale `vaultSalt` erases the PIN
  - PIN format and weak-PIN rules
  - the validator accepts and rejects the new messages
- README (features, security notes: "the PIN works only on this machine; files and backups still need the master
  password") and a CHANGELOG entry.
