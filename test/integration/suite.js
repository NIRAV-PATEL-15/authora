// Runs inside a real VS Code extension host (see run.sh). Plain JS, no test framework.
const vscode = require("vscode");
const assert = require("assert");

exports.run = async function () {
  const log = (m) => console.log("[it] " + m);
  const ext = vscode.extensions.getExtension("NiravPatel15.authora");
  assert.ok(ext, "extension found");
  const api = await ext.activate();
  const s = api.session;
  const cmds = await vscode.commands.getCommands(true);
  for (const c of ["authora.copyCode", "authora.unlock", "authora.lock", "authora.import", "authora.exportBackup"]) {
    assert.ok(cmds.includes(c), "command registered: " + c);
  }
  log("commands registered");

  assert.strictEqual(s.viewState().screen, "setup");
  await s.create("correct horse battery");
  assert.strictEqual(s.viewState().screen, "unlocked");
  await s.mutate(() => s.store.add({ id: "a1", type: "totp", issuer: "GitHub", account: "me", secret: "JBSWY3DPEHPK3PXP", period: 30, digits: 6, algorithm: "SHA1", counter: 0, pinned: false }));
  const st = s.viewState();
  assert.strictEqual(st.entries.length, 1);
  assert.match(st.entries[0].code, /^\d{6}$/);
  assert.ok(!JSON.stringify(st).includes("JBSWY3DPEHPK3PXP"), "secret not in view state");
  log("vault created, code " + st.entries[0].code);

  await s.copyCode(s.store.entries[0]);
  assert.strictEqual(await vscode.env.clipboard.readText(), st.entries[0].code);
  log("copy works");

  await vscode.commands.executeCommand("authora.accounts.focus");
  await new Promise((r) => setTimeout(r, 1500));
  log("view focused");

  await vscode.commands.executeCommand("authora.lock");
  assert.strictEqual(s.viewState().screen, "locked");
  await assert.rejects(() => s.unlock("nope"));
  await s.unlock("correct horse battery");
  assert.strictEqual(s.store.entries[0].issuer, "GitHub");
  log("lock/unlock works");

  // ---- quick-unlock PIN ----
  assert.strictEqual(s.viewState().offerPin, "afterCreate", "new vault is offered a PIN");
  await s.setPin("482913");
  assert.strictEqual(s.viewState().settings.pinSet, true);
  assert.strictEqual(s.viewState().offerPin, undefined);
  await s.lock();
  assert.ok(s.viewState().pin, "locked screen knows a PIN exists");
  await s.unlockWithPin("482913");
  assert.strictEqual(s.viewState().screen, "unlocked");
  await s.lock();
  for (let i = 0; i < 3; i++) await assert.rejects(() => s.unlockWithPin("000001"));
  assert.ok(s.viewState().pin.lockedMs > 0, "3 wrong PINs lock the PIN");
  await s.unlock("correct horse battery");
  assert.strictEqual(s.pin.status().failures, 0, "password unlock resets PIN failures");
  const { hadPin } = await s.changePassword("correct horse battery", "correct horse battery 2");
  assert.strictEqual(hadPin, true);
  assert.strictEqual(s.pin.hasPin, false, "password change erases the PIN");
  log("PIN works");
  log("ALL PASSED");
};
