# PIN Quick Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional 6-digit PIN that unlocks Authora on this machine, auto-submitting on the 6th digit, with the master password kept as the fallback and the file and backup protection.

**Architecture:** The vault key is wrapped with the PIN (Argon2id + AES-GCM envelope) and stored in VS Code SecretStorage. A pure core `PinManager` holds the wrap/unwrap and the attempt rules (3 → 1-min lock, 9 → erase). The attempt state is persisted in a small file beside the vault and updated under the vault's lock file. `Session` wires the manager to VS Code. The webview gets a shared six-box component and new screens and sheets. The command palette uses an auto-accepting `InputBox`.

**Tech Stack:** TypeScript, VS Code API 1.85, hash-wasm (Argon2id), node:crypto, vitest, esbuild.

**Spec:** `docs/superpowers/specs/2026-11-26-pin-unlock-design.md`

## Global Constraints
- PIN format exactly `/^\d{6}$/`. Weak PINs are rejected with the text **"Too easy to guess"**.
- Wrong PINs: at 3 and 6 failures, lock the PIN for **60 000 ms**. At **9** failures, erase the PIN and reset the counters.
- Erase message: **"Too many wrong PINs. PIN erased. Unlock with your master password."**
- (i) text on PIN screens: **"3 wrong PINs lock the PIN for 1 minute. After 9 wrong PINs in a row, the PIN is erased and you'll need your master password."**
- The vault file format, backups and exports are unchanged. The PIN never opens `vault.json` or a backup.
- No PIN, derived key or vault key is sent to the webview or logged.
- The SecretStorage key is `authora.pin`. The globalState key is `authora.pinOfferShown`.
- **Deviation from the spec (decided while planning):** the attempt state lives in `<globalStorage>/pin-attempts.json` instead of `globalState`. `globalState` is cached per window, so cross-window updates could still be lost even under the lock. A file under the vault lock is truly shared and survives reloads, which is what the spec intends.

## Review Focus
1. SecretStorage throws or is unavailable → treated as "no PIN"; password unlock still works (Task 2 test).
2. `pin-attempts.json` corrupted or missing → treated as 0 failures, no crash (Task 2 test).
3. `lockedUntil` far in the future (clock moved back, or the file was edited) → remaining wait capped at 60 s (Task 2 test).
4. Vault re-keyed by another window → the PIN is erased as stale and the attempt isn't counted (Task 2 test).
5. A non-6-digit or non-string `pin` in a webview message → rejected by the validator, never reaches the host (Task 3 test).

---

### Task 1: PIN rules (shared) and the vault lock hook

**Files:**
- Create: `src/shared/pin.ts`
- Modify: `src/core/vault.ts` (expose the lock and the salt)
- Test: `test/pin.test.ts`

**Interfaces:**
- Produces:
  - `isPinFormat(s: unknown): s is string`
  - `isWeakPin(pin: string): boolean`
  - `PIN_INFO_TEXT: string` (the (i) text above)
  - `VaultStore.withLock<T>(fn: () => Promise<T> | T): Promise<T>` (rename the private `withFileLock` to public `withLock`; update the internal callers)
  - `VaultStore.currentSalt(): string` (reads the envelope via `readEnvelope()`, works while locked)

- [ ] **Step 1: Write the failing tests** in `test/pin.test.ts`:
```ts
describe("pin rules", () => {
  it("format", () => {
    expect(isPinFormat("482913")).toBe(true);
    for (const bad of ["12345", "1234567", "12a456", " 123456", 123456, undefined]) expect(isPinFormat(bad)).toBe(false);
  });
  it("weak pins", () => {
    for (const w of ["000000", "999999", "123456", "654321", "012345", "987654", "121212", "123123", "112233"]) expect(isWeakPin(w)).toBe(true);
    for (const ok of ["482913", "730215", "246810"]) expect(isWeakPin(ok)).toBe(false);
  });
  it("currentSalt works while locked", async () => {
    const v = new VaultStore(file, FAST_KDF_FOR_TESTS); await v.create("password1"); v.lock();
    expect(v.currentSalt()).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});
```
- [ ] **Step 2:** Run `npx vitest run test/pin.test.ts`. Expected: FAIL (module not found).
- [ ] **Step 3:** Implement `src/shared/pin.ts` (no Node imports, because the webview bundles it). Weak means all digits the same; or every step +1 or −1 across all 6 digits; or the pattern `ababab`, `abcabc` or `aabbcc`. Then make the two `VaultStore` changes.
- [ ] **Step 4:** Run `npm test`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat(pin): PIN format and weak-PIN rules`.

### Task 2: Core PinManager (wrap, attempts, erase)

**Files:**
- Create: `src/core/pin.ts`
- Test: `test/pin.test.ts` (extend)

**Interfaces:**
- Consumes: `seal`, `open`, `KdfCost`, `DEFAULT_KDF`, `WrongPasswordError` from `envelope.ts`; `isPinFormat` and `isWeakPin` from Task 1.
- Produces:
```ts
export const PIN_LOCK_MS = 60_000, PIN_FAILS_PER_LOCK = 3, PIN_MAX_FAILS = 9;
export interface SecretSlot { get(): Promise<string | undefined>; store(v: string): Promise<void>; delete(): Promise<void>; }
export interface PinStatus { lockedMs: number; failures: number }
export class PinLockedError extends Error { constructor(public waitMs: number) }      // "PIN locked. Try again in Ns"
export class PinInvalidError extends Error {}   // "PIN no longer valid. Use your master password."
export class WrongPinError extends Error { constructor(public erased: boolean, public triesBeforeLock: number) }
export class PinManager {
  constructor(slot: SecretSlot, attemptsFile: string, withLock: <T>(fn: () => Promise<T> | T) => Promise<T>,
              cost?: KdfCost, now?: () => number)
  get hasPin(): boolean                     // cached; false until load() resolves
  load(): Promise<void>                     // any slot error → hasPin=false
  status(): PinStatus                       // sync read of attemptsFile; corrupt → {0,0}; lockedMs capped at PIN_LOCK_MS
  set(key: Buffer, pin: string, vaultSalt: string): Promise<void>  // throws Error("Too easy to guess") / format error; resets attempts
  remove(): Promise<void>
  resetAttempts(): Promise<void>
  /** Unwraps the vault key and hands it to `verify(key)`, which unlocks the vault or throws WrongPasswordError if the key doesn't open it. */
  unlock(pin: string, vaultSalt: string, verify: (key: Buffer) => Promise<void>): Promise<void>
}
```
Slot JSON is `{ vaultSalt, env }`, where `env = await seal(key.toString("base64"), pin, cost)`. Flow inside `unlock`:
1. Locked → `PinLockedError`.
2. No slot, or `slot.vaultSalt !== vaultSalt` → `remove()` and throw `PinInvalidError`, without counting the attempt.
3. Run `open(env, pin)`:
   - On `WrongPasswordError`, under `withLock`, read the attempts, increment, and write them back. At 9, `remove()` and reset, then throw `WrongPinError(true, 0)`. At a multiple of 3, set `lockedUntil` and throw `WrongPinError(false, 0)`. Otherwise throw `WrongPinError(false, 3 - failures % 3)`.
   - On success, call `verify(key)`. If that throws `WrongPasswordError`, `remove()` and throw `PinInvalidError`. Otherwise `resetAttempts()`.

- [ ] **Step 1: Write the failing tests** (in-memory `SecretSlot` fake, `FAST_KDF_FOR_TESTS`, fake clock; `withLock` = a real `VaultStore.withLock`):
  - `set then unlock with the right PIN calls verify with the vault key` (compare bytes)
  - `wrong PIN: triesBeforeLock 2, then 1, then locked` → third throws `WrongPinError` and `status().lockedMs === 60000`; an immediate retry throws `PinLockedError`
  - `after lock expires (clock +60001) counting continues; 6th failure locks again; 9th erases` → `erased === true`, `hasPin === false`, `status()` → `{lockedMs:0, failures:0}`
  - `success resets failures`
  - `resetAttempts clears lock` (used by password unlock)
  - `stale vaultSalt → PinInvalidError, PIN removed, failures unchanged`
  - `verify throws WrongPasswordError → PinInvalidError and PIN removed`
  - Review Focus 1: `slot.get throws → load() leaves hasPin false`
  - Review Focus 2: `corrupt attempts file ("{x") → status() is {0,0}`
  - Review Focus 3: `lockedUntil = now + 10 h in the file → status().lockedMs === 60000`
  - `set rejects weak and malformed PINs`
- [ ] **Step 2:** Run `npx vitest run test/pin.test.ts`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement `src/core/pin.ts` as specified. Write the attempts file with `writeFileSync(..., { mode: 0o600 })` via a temp file and rename.
- [ ] **Step 4:** Run `npm test && npm run typecheck`. Expected: pass.
- [ ] **Step 5:** Commit: `feat(pin): PinManager with wrap, attempt limits and erase`.

### Task 3: Protocol, validation, Session and provider

**Files:**
- Modify: `src/shared/protocol.ts`, `src/shared/validate.ts`, `src/host/session.ts`, `src/host/provider.ts`
- Test: `test/security.test.ts` (validator cases)

**Interfaces:**
- Consumes: `PinManager` and the errors from Task 2; `isPinFormat` from Task 1.
- Produces (protocol):
  - `ViewState.locked.pin?: { lockedMs: number; failures: number }`
  - `ViewState.unlocked.settings.pinSet: boolean`
  - `ViewState.unlocked.offerPin?: "afterCreate" | "newFeature"`
  - `ViewMsg`: `{type:"unlockPin"; pin: string; remember: boolean}`, `{type:"setPin"; pin: string}`, `{type:"removePin"}`, `{type:"dismissPinOffer"}`
  - `HostMsg`: `{type:"pinAgain"}`
- Produces (Session):
  - `readonly pin: PinManager` (slot = `ctx.secrets` key `authora.pin`, file `<globalStorage>/pin-attempts.json`, lock = `store.withLock`; `void pin.load().then(() => this.fire())` in the constructor)
  - `unlockWithPin(pin: string): Promise<void>` calls `pin.unlock(pin, store.currentSalt(), (k) => store.unlockWithKey(k))`, then does the same post-steps as `unlock()` (clear `requirePassword`, touch, `syncRememberedKey`, fire)
  - `unlock(password)` also calls `pin.resetAttempts()`
  - `setPin(pin: string)` wraps `store.exportKey()` and sets `pinOfferShown=true`; `removePin()`; `dismissPinOffer()`
  - `changePassword(oldPw, newPw): Promise<{ hadPin: boolean }>` moves the store call, `syncRememberedKey` and `autoBackup` out of provider and extension; removes the PIN if one existed
  - `justCreated` flag (set in `create()`, cleared by `setPin` and `dismissPinOffer`) → `offerPin` is `"afterCreate"` if `justCreated`, otherwise `"newFeature"` when `!pin.hasPin && !pinOfferShown`

- [ ] **Step 1: Write the failing validator tests** in `test/security.test.ts`:
```ts
it("validates PIN messages", () => {
  expect(isValidViewMsg({ type: "unlockPin", pin: "482913", remember: false })).toBe(true);
  expect(isValidViewMsg({ type: "setPin", pin: "482913" })).toBe(true);
  expect(isValidViewMsg({ type: "removePin" })).toBe(true);
  expect(isValidViewMsg({ type: "dismissPinOffer" })).toBe(true);
  for (const pin of ["48291", "4829134", "48a913", 482913, null]) {
    expect(isValidViewMsg({ type: "unlockPin", pin, remember: false })).toBe(false);
    expect(isValidViewMsg({ type: "setPin", pin })).toBe(false);
  }
});
```
- [ ] **Step 2:** Run `npx vitest run test/security.test.ts`. Expected: FAIL.
- [ ] **Step 3:** Update the protocol and validator, then Session, then the provider cases:
  - `unlockPin` (form `"unlockPin"`):
    - first update `rememberOnThisMachine` exactly like `unlock`;
    - map `WrongPinError` to `"Wrong PIN · N tries before a 1-minute lock"` when `triesBeforeLock>0`, else `"PIN locked for 1 minute"`; after 6+ failures say `"Wrong PIN · next wrong PINs erase it"`; when erased, use the erase message;
    - map `PinLockedError` to its message;
    - map `PinInvalidError` to its message;
    - always `pushState()` after a PIN error so the countdown and the screen fallback update.
  - `setPin` posts `done` + toast `"PIN set"`.
  - `removePin` shows a modal confirm `"Remove your quick-unlock PIN?"` → `"Remove"`.
  - `dismissPinOffer`.
  - `changePassword` uses `s.changePassword` and posts `{type:"pinAgain"}` when `hadPin`.
  - Add `"unlockPin"` and `"setPin"` to the no-toast form list.
- [ ] **Step 4:** Run `npm test && npm run typecheck`. Expected: pass.
- [ ] **Step 5:** Commit: `feat(pin): host session, protocol and provider wiring`.

### Task 4: Command palette PIN prompt

**Files:**
- Modify: `src/extension.ts`
- Test: `test/integration/suite.js` (extend)

**Interfaces:**
- Consumes: `Session.pin`, `unlockWithPin`, `setPin`, `changePassword` from Task 3.
- Produces: `promptPin(s: Session): Promise<"unlocked" | "usePassword" | "cancel">` (module-local).

- [ ] **Step 1: Write the failing integration test.** After the existing create step in `suite.js`:
  - `await s.setPin("482913"); await s.lock();`
  - assert `s.viewState().pin` is defined;
  - `await s.unlockWithPin("482913")`, then assert unlocked;
  - lock again; three wrong `unlockWithPin("000001")` calls reject, and `s.viewState().pin.lockedMs > 0`;
  - `await s.unlock(<password>)`, then assert `s.pin.status().failures === 0`.
- [ ] **Step 2:** Run `npm run test:integration`. Expected: FAIL (until Task 3 is complete, `setPin` doesn't exist; if Task 3 is done, this passes, and the step only verifies the wiring).
- [ ] **Step 3:** Implement `promptPin` and wire it in:
  - Build it on `vscode.window.createInputBox()` with `password: true` and the title `"Authora PIN"`.
  - Add a button `{ iconPath: new vscode.ThemeIcon("key"), tooltip: "Use master password" }` that resolves `"usePassword"`.
  - In `onDidChangeValue`, set `validationMessage` for non-digits. When the value matches `/^\d{6}$/`, set `busy`, call `unlockWithPin`, and on success resolve `"unlocked"`.
  - On `WrongPinError` without a lock, clear the value and set `validationMessage`.
  - On a lock, erase or invalid PIN, hide the box, show a warning message and resolve `"usePassword"`. Hiding otherwise resolves `"cancel"`.
  - `ensureUnlocked`: if `s.pin.hasPin && s.pin.status().lockedMs === 0`, run `promptPin` first; on `"usePassword"`, fall through to the existing password box.
  - `authora.changePassword`: use `s.changePassword`; if `hadPin`, ask for the new PIN twice with two `showInputBox`es (`password:true`, validate the format and weak rule). Escape on either skips. Mismatch → error message.
- [ ] **Step 4:** Run `npm run typecheck && npm test && npm run test:integration`. Expected: pass.
- [ ] **Step 5:** Commit: `feat(pin): PIN prompt in the command palette`.

### Task 5: Webview six-box component and screens

**Files:**
- Modify: `webview/main.ts`, `media/main.css`

**Interfaces:**
- Consumes: the protocol additions from Task 3; `isPinFormat`, `isWeakPin` and `PIN_INFO_TEXT` from `src/shared/pin.ts`.
- Produces (module-local):
  - `pinBoxes(onComplete: (pin: string) => void, opts?: { autofocus?: boolean }): { el: HTMLElement; clear(shake?: boolean): void; setDisabled(d: boolean): void; focus(): void }`
  - `infoIcon(text: string): HTMLElement`
  - `Sheet` gains `{ kind: "pinSetup"; mode: "afterCreate" | "newFeature" | "settings" | "again" }`

- [ ] **Step 1: Build `pinBoxes` and `infoIcon`**, matching the approved mockup (`.superpowers/brainstorm/*/content/pin-screens-v2.html`):
  - 36×44 boxes with masked digits (`-webkit-text-security: disc`) and `inputmode="numeric"`;
  - auto-advance, Backspace steps back, paste fills all six;
  - the shake animation reuses `@keyframes shake`;
  - the info icon is an `<span class="info" tabindex="0">` with a hover or focus tooltip.
  - Add the CSS to `media/main.css` using the existing tokens.
- [ ] **Step 2: Locked screen.**
  - When `state.pin` exists, `renderLocked` shows the PIN view by default:
    - orb, "Vault locked", "Enter your PIN" + `infoIcon(PIN_INFO_TEXT)`, the boxes, "Remember on this machine", and the link "Use master password";
    - completing the boxes sends `unlockPin`;
    - while `state.pin.lockedMs > 0`, the boxes are disabled with a live `PIN locked · try again in m:ss` and the link highlighted.
  - The password view gets a "Use PIN" link when `state.pin` exists.
  - A local `preferPassword` flag survives re-renders on the same locked state and resets to the PIN view on each new lock.
  - `setError("unlockPin", …)` shakes and clears the boxes.
  - When a state arrives without `pin` after a PIN error, show the password view and carry the last error text into its error box.
- [ ] **Step 3: `pinSetup` sheet.**
  - Flow: "Set a 6-digit PIN" + info → "Confirm your PIN" → on a match send `setPin`.
  - Weak PIN → "Too easy to guess. Choose another PIN." Mismatch → "PINs don't match. Start again." Both shake and restart.
  - Per mode:
    - `afterCreate` has the link "Skip for now" (sends `dismissPinOffer`);
    - `newFeature` starts with an intro ("✨ New: quick-unlock PIN", "Unlock Authora with a 6-digit PIN instead of typing your master password.") and the buttons **Set up PIN** and **Not now** (`dismissPinOffer`);
    - `settings` has the normal back arrow to Security;
    - `again` has the title "Set your PIN again" and the link "Skip".
  - The `done` for `setPin` closes the sheet.
- [ ] **Step 4: Wiring.**
  - In `render()`, when unlocked, `state.offerPin` set and `sheet === null`, open `pinSetup` with that mode.
  - Add `"pinAgain"` to the message handler, which opens `{kind:"pinSetup", mode:"again"}`.
  - Security sheet: a row "Quick-unlock PIN" with an On/Off pill. It shows **Set up** when off (opens `pinSetup` in `settings` mode), and **Change** and **Remove** when on. Remove sends `removePin`.
  - Re-render the Security sheet on state updates (already handled for `security`).
- [ ] **Step 5:** Run `npm run typecheck && npm run build`. Expected: no errors. Then run `npm run test:integration` to make sure nothing regressed.
- [ ] **Step 6:** Manual check in the Extension Development Host (F5):
  - fresh vault → PIN offer → set it → lock → the PIN unlocks on the 6th digit;
  - 3 wrong PINs → countdown; 9 wrong PINs → password screen with the erase message;
  - Settings → Change and Remove;
  - change the master password → "Set your PIN again";
  - `Ctrl+Alt+2` while locked → the PIN box auto-accepts.
- [ ] **Step 7:** Commit: `feat(pin): six-box PIN UI, setup sheet, settings row`.

### Task 6: Docs

**Files:**
- Modify: `README.md`, `CHANGELOG.md`

- [ ] **Step 1: README.**
  - Features: a "Quick-unlock PIN" bullet.
  - Security notes: "The PIN works only on this computer (OS keychain). The vault file and backups still need the master password. 3 wrong PINs → 1-minute lock; 9 → PIN erased."
- [ ] **Step 2: CHANGELOG.** Add a `## 0.2.0 — unreleased` section. It describes the PIN, the auto-submit, the limits, the one-time "New" pop-up and the Settings controls.
- [ ] **Step 3:** Run `npm test && npm run typecheck`, then commit: `docs: PIN quick unlock`.
