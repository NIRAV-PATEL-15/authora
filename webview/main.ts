import jsQR from "jsqr";
import type { EntryView, HostMsg, ManualEntry, ViewMsg, ViewState } from "../src/shared/protocol";
import type { Insight } from "../src/core/advisor";

declare function acquireVsCodeApi(): { postMessage(m: ViewMsg): void };
const vscode = acquireVsCodeApi();
const send = (m: ViewMsg) => vscode.postMessage(m);

// ---------- tiny DOM helpers ----------
type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, unknown> = {},
  ...children: (Child | Child[])[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    else if (k === "class") el.className = String(v);
    else if (k === "html") el.innerHTML = String(v);
    else if (k in el && k !== "list" && k !== "type") (el as unknown as Record<string, unknown>)[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c as Node | string);
  return el;
}
const $ = (sel: string) => document.querySelector(sel) as HTMLElement | null;

const ICONS: Record<string, string> = {
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  more: '<circle cx="12" cy="5" r="1.4"/><circle cx="12" cy="12" r="1.4"/><circle cx="12" cy="19" r="1.4"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  pin: '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
  qr: '<rect x="4" y="4" width="6" height="6"/><rect x="14" y="4" width="6" height="6"/><rect x="4" y="14" width="6" height="6"/><path d="M14 14h2v2h-2zM18 18h2v2h-2zM14 18h2M18 14h2"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v4h16v-4"/>',
  download: '<path d="M12 4v12M7 11l5 5 5-5"/><path d="M4 16v4h16v-4"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  alert: '<path d="M12 3 2 21h20z"/><path d="M12 10v5M12 18v.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  folder: '<path d="M3 6h6l2 2h10v11H3z"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 17-5-5-8 8"/>',
  link: '<path d="M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1"/><path d="M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>',
  back: '<path d="m15 6-6 6 6 6"/>',
};
function icon(name: string, cls = "") {
  const span = h("span", { class: `icon ${cls}` });
  span.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
  return span;
}
function iconBtn(name: string, title: string, onClick: (e: MouseEvent) => void, cls = "") {
  return h("button", { class: `icon-btn ${cls}`, title, "aria-label": title, onClick }, icon(name));
}

// ---------- state ----------
let state: ViewState | null = null;
let codes: Record<string, string> = {};
let query = "";
let lastScreen = "";
let lastCounters: Record<string, number> = {};
type Sheet =
  | { kind: "add"; tab: "qr" | "uri" | "manual" }
  | { kind: "edit"; id: string }
  | { kind: "menu" }
  | { kind: "backup" }
  | { kind: "password" }
  | { kind: "security" }
  | { kind: "advisor" }
  | { kind: "qr"; label: string; svg: string }
  | { kind: "importPassword"; text: string; format: string };
let sheet: Sheet | null = null;

const entries = (): EntryView[] => (state?.screen === "unlocked" ? state.entries : []);

// ---------- helpers ----------
function hue(s: string) {
  let x = 0;
  for (const c of s) x = (x * 31 + c.charCodeAt(0)) >>> 0;
  return x % 360;
}
function formatCode(code: string) {
  if (!code) return "------";
  if (!/^\d+$/.test(code)) return code;
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  if (code.length === 7) return `${code.slice(0, 3)} ${code.slice(3)}`;
  return code;
}
function nowSec() {
  const off = state?.screen === "unlocked" ? state.offset : 0;
  return Date.now() / 1000 + off;
}
function periodOf(e: EntryView) {
  return e.type === "totp" || e.type === "hex" ? e.period : 30;
}
function strength(pw: string): { score: number; label: string } {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^\w\s]/.test(pw)) s++;
  if (pw.length >= 16) s++;
  const score = Math.min(4, Math.floor((s * 4) / 6));
  return { score, label: ["Too weak", "Weak", "Fair", "Good", "Strong"][score] };
}
function timeAgo(ts?: number) {
  if (!ts) return "never";
  const d = (Date.now() - ts) / 1000;
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} days ago`;
}

// ---------- toasts ----------
function toast(text: string, kind: "ok" | "error" | undefined = undefined) {
  let host = $("#toasts");
  if (!host) { host = h("div", { id: "toasts" }); document.body.append(host); }
  const t = h("div", { class: `toast ${kind || ""}` }, kind === "error" ? icon("alert") : icon("shield"), h("span", {}, text));
  host.append(t);
  setTimeout(() => t.classList.add("out"), 2600);
  setTimeout(() => t.remove(), 3000);
}

// ---------- form helpers ----------
function field(labelText: string, input: HTMLElement, hint?: string) {
  return h("label", { class: "field" }, h("span", { class: "field-label" }, labelText), input, hint ? h("span", { class: "hint" }, hint) : null);
}
function pwInput(name: string, placeholder = "", autofocus = false) {
  const inp = h("input", { type: "password", name, placeholder, autocomplete: "off", spellcheck: false }) as HTMLInputElement;
  inp.setAttribute("type", "password");
  if (autofocus) setTimeout(() => inp.focus(), 30);
  const eye = h("button", { type: "button", class: "eye", title: "Show/hide", onClick: () => {
    inp.type = inp.type === "password" ? "text" : "password";
  } }, icon("eye"));
  return h("div", { class: "pw-wrap" }, inp, eye);
}
function errorBox(form: string) {
  return h("div", { class: "form-error", "data-form": form });
}
function setError(form: string, text: string) {
  document.querySelectorAll<HTMLElement>(`.form-error[data-form="${form}"]`).forEach((el) => {
    el.textContent = text;
    el.classList.toggle("show", !!text);
  });
  document.querySelectorAll<HTMLButtonElement>(`button[data-busy-form="${form}"]`).forEach((b) => b.classList.remove("busy"));
}
function busy(btn: HTMLButtonElement, form: string) {
  btn.dataset.busyForm = form;
  btn.classList.add("busy");
  setError(form, "");
}
const val = (root: HTMLElement, name: string) => (root.querySelector(`[name="${name}"]`) as HTMLInputElement).value;

// ---------- screens ----------
function renderSetup() {
  const form = h("form", { class: "auth-card", onSubmit: (ev: Event) => {
    ev.preventDefault();
    const pw = val(form, "pw");
    const pw2 = val(form, "pw2");
    if (pw.length < 8) return setError("create", "Use at least 8 characters");
    if (pw !== pw2) return setError("create", "Passwords don't match");
    busy(btn, "create");
    send({ type: "create", password: pw });
  } });
  const meter = h("div", { class: "meter" }, h("div", { class: "meter-bar" }));
  const meterLabel = h("span", { class: "meter-label" }, "");
  const pw = pwInput("pw", "Master password", true);
  pw.querySelector("input")!.addEventListener("input", (e) => {
    const s = strength((e.target as HTMLInputElement).value);
    meter.dataset.score = String(s.score);
    meterLabel.textContent = (e.target as HTMLInputElement).value ? s.label : "";
  });
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Create vault");
  form.append(
    h("div", { class: "brand" }, icon("shield", "brand-icon"), h("h1", {}, "Create your vault"),
      h("p", { class: "muted" }, "Your 2FA secrets are encrypted with this password using Argon2id + AES-256-GCM. It never leaves this machine.")),
    field("Master password", pw),
    h("div", { class: "meter-row" }, meter, meterLabel),
    field("Confirm password", pwInput("pw2", "Repeat password")),
    h("div", { class: "notice" }, icon("alert"), h("span", {}, "There is no recovery. If you forget this password, the vault cannot be opened.")),
    errorBox("create"),
    btn,
  );
  return h("div", { class: "auth" }, form);
}

function renderLocked(throttledMs: number | undefined, rememberOn: boolean) {
  const remember = h("input", { type: "checkbox", name: "remember", checked: rememberOn }) as HTMLInputElement;
  remember.setAttribute("type", "checkbox");
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Unlock");
  const form = h("form", { class: "auth-card", onSubmit: (ev: Event) => {
    ev.preventDefault();
    const pw = val(form, "pw");
    if (!pw) return;
    busy(btn, "unlock");
    send({ type: "unlock", password: pw, remember: remember.checked });
  } },
    h("div", { class: "brand" }, h("div", { class: "lock-orb" }, icon("lock")), h("h1", {}, "Vault locked"),
      h("p", { class: "muted" }, "Enter your master password to see your codes.")),
    pwInput("pw", "Master password", true),
    h("label", { class: "check" }, remember, h("span", {}, "Remember on this machine (OS keychain)")),
    errorBox("unlock"),
    btn,
  );
  if (throttledMs && throttledMs > 0) {
    btn.disabled = true;
    const until = Date.now() + throttledMs;
    const tick = () => {
      const left = Math.ceil((until - Date.now()) / 1000);
      if (left <= 0) { btn.disabled = false; btn.textContent = "Unlock"; return; }
      btn.textContent = `Try again in ${left}s`;
      setTimeout(tick, 250);
    };
    tick();
  }
  return h("div", { class: "auth" }, form);
}

function renderUnlockedShell() {
  const search = h("input", { class: "search", placeholder: "Search accounts", value: query, spellcheck: false, onInput: (e: Event) => {
    query = (e.target as HTMLInputElement).value;
    renderList();
  } }) as HTMLInputElement;
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const first = filtered()[0];
      if (first) send({ type: "copy", id: first.id });
    } else if (e.key === "Escape") { query = ""; search.value = ""; renderList(); }
  });
  const header = h("header", { class: "topbar" },
    h("div", { class: "search-wrap" }, icon("search"), search),
    iconBtn("plus", "Add account", () => openSheet({ kind: "add", tab: "qr" }), "accent"),
    iconBtn("more", "Menu", () => openSheet({ kind: "menu" })),
    iconBtn("lock", "Lock vault", () => send({ type: "lock" })),
  );
  return h("div", { class: "shell" }, header, h("div", { id: "insights" }), h("main", { id: "list" }), h("div", { id: "sheet-host" }));
}

function filtered(): EntryView[] {
  const q = query.trim().toLowerCase();
  const list = [...entries()].sort((a, b) => Number(b.pinned) - Number(a.pinned));
  return q ? list.filter((e) => `${e.issuer} ${e.account}`.toLowerCase().includes(q)) : list;
}

function renderInsights() {
  const host = $("#insights");
  if (!host || state?.screen !== "unlocked") return;
  host.replaceChildren();
  const top = state.insights.find((i) => i.level === "danger") || state.insights[0];
  if (!top) return;
  host.append(h("button", { class: `insight ${top.level}`, onClick: () => openSheet({ kind: "advisor" }) },
    icon("alert"), h("span", {}, top.title), state.insights.length > 1 ? h("span", { class: "badge" }, `+${state.insights.length - 1}`) : null, icon("chevron")));
}

let dragId: string | null = null;
function renderList() {
  const host = $("#list");
  if (!host || state?.screen !== "unlocked") return;
  const list = filtered();
  host.replaceChildren();
  if (!entries().length) {
    host.append(h("div", { class: "empty" },
      h("div", { class: "empty-orb" }, icon("shield")),
      h("h2", {}, "No accounts yet"),
      h("p", { class: "muted" }, "Add your first account by scanning a QR image, pasting an otpauth:// link, or importing a backup."),
      h("button", { class: "btn primary", onClick: () => openSheet({ kind: "add", tab: "qr" }) }, icon("plus"), "Add account")));
    return;
  }
  if (!list.length) { host.append(h("div", { class: "empty small" }, h("p", { class: "muted" }, `No accounts match "${query}"`))); return; }
  const hide = state.settings.hideCodes;
  for (const e of list) {
    const code = codes[e.id] ?? e.code;
    const name = e.issuer || e.account || "Unnamed";
    const card = h("div", {
      class: `card ${hide ? "hide-code" : ""} ${e.pinned ? "pinned" : ""}`, draggable: !query, "data-id": e.id, tabindex: 0,
      title: "Click to copy",
      onClick: (ev: MouseEvent) => { if ((ev.target as HTMLElement).closest(".card-actions")) return; copy(e.id, card); },
      onKeydown: (ev: KeyboardEvent) => { if (ev.key === "Enter") copy(e.id, card); },
      onDragstart: (ev: DragEvent) => { dragId = e.id; card.classList.add("dragging"); ev.dataTransfer?.setData("text/plain", e.id); },
      onDragend: () => { dragId = null; card.classList.remove("dragging"); document.querySelectorAll(".drop-target").forEach((x) => x.classList.remove("drop-target")); },
      onDragover: (ev: DragEvent) => { if (dragId && dragId !== e.id) { ev.preventDefault(); card.classList.add("drop-target"); } },
      onDragleave: () => card.classList.remove("drop-target"),
      onDrop: (ev: DragEvent) => {
        ev.preventDefault();
        if (!dragId || dragId === e.id) return;
        const ids = list.map((x) => x.id).filter((id) => id !== dragId);
        ids.splice(ids.indexOf(e.id), 0, dragId);
        send({ type: "reorder", ids });
      },
    },
      h("div", { class: "avatar", style: `--h:${hue(name.toLowerCase())}` }, name.charAt(0).toUpperCase()),
      h("div", { class: "card-main" },
        h("div", { class: "card-title" }, h("span", { class: "issuer" }, name), e.pinned ? icon("pin", "pin-mark") : null,
          e.type !== "totp" ? h("span", { class: "chip" }, e.type.toUpperCase()) : null),
        e.issuer && e.account ? h("div", { class: "account" }, e.account) : null,
        h("div", { class: `code ${code ? "" : "invalid"}`, "data-code": e.id }, code ? formatCode(code) : "Invalid secret")),
      h("div", { class: "card-side" },
        e.counterBased
          ? iconBtn("refresh", "Next code", () => send({ type: "next", id: e.id }), "next-btn")
          : ring(e),
        h("div", { class: "card-actions" },
          iconBtn("pin", e.pinned ? "Unpin" : "Pin", () => send({ type: "pin", id: e.id })),
          iconBtn("edit", "Edit", () => openSheet({ kind: "edit", id: e.id })),
          iconBtn("qr", "Show QR", () => send({ type: "showQr", id: e.id })),
        )),
    );
    host.append(card);
  }
  tick();
}

function ring(e: EntryView) {
  const wrap = h("div", { class: "ring", "data-ring": e.id, "data-period": periodOf(e) });
  wrap.innerHTML = `<svg viewBox="0 0 36 36"><circle class="track" cx="18" cy="18" r="15"/><circle class="prog" cx="18" cy="18" r="15" pathLength="100"/></svg><span class="secs"></span>`;
  return wrap;
}

function copy(id: string, card: HTMLElement) {
  card.classList.remove("copied");
  void card.offsetWidth;
  card.classList.add("copied");
  send({ type: "copy", id });
}

function tick() {
  if (state?.screen !== "unlocked") return;
  const t = nowSec();
  let needRefresh = false;
  for (const e of state.entries) {
    if (e.counterBased) continue;
    const p = periodOf(e);
    const counter = Math.floor(t / p);
    if (lastCounters[e.id] !== undefined && lastCounters[e.id] !== counter) needRefresh = true;
    lastCounters[e.id] = counter;
  }
  document.querySelectorAll<HTMLElement>("[data-ring]").forEach((el) => {
    const p = Number(el.dataset.period);
    const left = p - (t % p);
    const pct = (left / p) * 100;
    const prog = el.querySelector<SVGCircleElement>(".prog")!;
    prog.style.strokeDashoffset = String(100 - pct);
    el.classList.toggle("urgent", left <= 5);
    el.querySelector(".secs")!.textContent = String(Math.ceil(left));
  });
  if (needRefresh) send({ type: "refresh" });
}
setInterval(tick, 250);

// ---------- sheets ----------
function openSheet(s: Sheet) {
  sheet = s;
  renderSheet();
}
function closeSheet() {
  sheet = null;
  renderSheet();
}
function sheetFrame(title: string, body: (HTMLElement | null)[], back?: () => void) {
  return h("div", { class: "sheet-backdrop", onClick: (e: MouseEvent) => { if (e.target === e.currentTarget) closeSheet(); } },
    h("section", { class: "sheet", role: "dialog", "aria-label": title },
      h("div", { class: "sheet-head" },
        back ? iconBtn("back", "Back", back) : null,
        h("h2", {}, title),
        iconBtn("x", "Close", closeSheet)),
      h("div", { class: "sheet-body" }, ...body)));
}

function renderSheet() {
  const host = $("#sheet-host");
  if (!host) return;
  host.replaceChildren();
  if (!sheet || state?.screen !== "unlocked") return;
  const s = sheet;
  let el: HTMLElement;
  switch (s.kind) {
    case "add": el = addSheet(s.tab); break;
    case "edit": el = editSheet(s.id); break;
    case "menu": el = menuSheet(); break;
    case "backup": el = backupSheet(); break;
    case "password": el = passwordSheet(); break;
    case "security": el = securitySheet(); break;
    case "advisor": el = advisorSheet(); break;
    case "qr": el = qrSheet(s.label, s.svg); break;
    case "importPassword": el = importPasswordSheet(s.text, s.format); break;
  }
  host.append(el);
  const f = host.querySelector<HTMLElement>("[autofocus], input:not([type=checkbox]), textarea");
  f?.focus();
}

function addSheet(tab: "qr" | "uri" | "manual") {
  const tabs = h("div", { class: "tabs" },
    ...(["qr", "uri", "manual"] as const).map((t) =>
      h("button", { class: `tab ${t === tab ? "active" : ""}`, onClick: () => openSheet({ kind: "add", tab: t }) },
        icon(t === "qr" ? "qr" : t === "uri" ? "link" : "edit"), t === "qr" ? "QR image" : t === "uri" ? "Link / text" : "Manual")));
  let body: HTMLElement;
  if (tab === "qr") {
    const fileIn = h("input", { type: "file", accept: "image/*", class: "hidden", onChange: (e: Event) => {
      const f = (e.target as HTMLInputElement).files?.[0];
      if (f) decodeQrBlob(f);
    } }) as HTMLInputElement;
    fileIn.setAttribute("type", "file");
    const drop = h("div", { class: "dropzone", tabindex: 0,
      onClick: () => fileIn.click(),
      onDragover: (e: DragEvent) => { e.preventDefault(); drop.classList.add("over"); },
      onDragleave: () => drop.classList.remove("over"),
      onDrop: (e: DragEvent) => { e.preventDefault(); drop.classList.remove("over"); const f = e.dataTransfer?.files?.[0]; if (f) decodeQrBlob(f); },
    }, icon("image", "big"), h("strong", {}, "Paste, drop or choose a QR image"),
      h("span", { class: "muted" }, "Take a screenshot of the QR code (e.g. Print Screen), then press Ctrl/Cmd+V here."));
    body = h("div", {}, drop, fileIn, errorBox("qr"), errorBox("importText"));
  } else if (tab === "uri") {
    const ta = h("textarea", { name: "text", rows: 6, placeholder: "otpauth://totp/Issuer:me?secret=…\notpauth-migration://offline?data=…", spellcheck: false });
    const btn = h("button", { class: "btn primary block" }, "Add");
    btn.addEventListener("click", () => {
      const text = (ta as HTMLTextAreaElement).value.trim();
      if (!text) return setError("importText", "Paste at least one link");
      busy(btn, "importText");
      send({ type: "importText", text });
    });
    body = h("div", {}, field("One or more links (one per line)", ta, "Google Authenticator export links are supported."), errorBox("importText"), btn);
  } else {
    body = manualForm();
  }
  const importBtn = h("button", { class: "btn ghost block", onClick: () => send({ type: "importFile" }) }, icon("upload"), "Import backup file…");
  return sheetFrame("Add account", [tabs, body, h("div", { class: "divider" }, "or"), importBtn,
    h("p", { class: "hint center" }, "Supports Chrome Authenticator, Google Authenticator, andOTP, 2FAS, Aegis and Vault 2FA backups.")]);
}

function manualForm() {
  const sel = (name: string, opts: string[], v: string) =>
    h("select", { name }, ...opts.map((o) => h("option", { value: o, selected: o === v }, o)));
  const advanced = h("details", { class: "advanced" }, h("summary", {}, "Advanced"),
    h("div", { class: "grid2" },
      field("Type", sel("type", ["totp", "hotp", "steam", "battle", "hex", "hhex"], "totp")),
      field("Algorithm", sel("algorithm", ["SHA1", "SHA256", "SHA512"], "SHA1")),
      field("Digits", h("input", { name: "digits", type: "number", min: 1, max: 10, value: 6 })),
      field("Period (s)", h("input", { name: "period", type: "number", min: 1, value: 30 })),
      field("Counter (HOTP)", h("input", { name: "counter", type: "number", min: 0, value: 0 }))));
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Add account");
  const form = h("form", { class: "form", onSubmit: (ev: Event) => {
    ev.preventDefault();
    const entry: ManualEntry = {
      issuer: val(form, "issuer"), account: val(form, "account"), secret: val(form, "secret"),
      type: val(form, "type") as ManualEntry["type"], algorithm: val(form, "algorithm") as ManualEntry["algorithm"],
      digits: Number(val(form, "digits")), period: Number(val(form, "period")), counter: Number(val(form, "counter")),
    };
    if (!entry.secret.trim()) return setError("addManual", "Secret is required");
    if (!entry.issuer.trim() && !entry.account.trim()) return setError("addManual", "Give it a name (issuer or account)");
    busy(btn, "addManual");
    send({ type: "addManual", entry });
  } },
    field("Issuer", h("input", { name: "issuer", placeholder: "GitHub" })),
    field("Account", h("input", { name: "account", placeholder: "you@example.com" })),
    field("Secret key", pwInput("secret", "Base32 secret, e.g. JBSW Y3DP EHPK 3PXP")),
    advanced, errorBox("addManual"), btn);
  return form;
}

async function decodeQrBlob(blob: Blob) {
  setError("qr", "");
  try {
    const bmp = await createImageBitmap(blob);
    const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const w = Math.round(bmp.width * scale), hgt = Math.round(bmp.height * scale);
    const canvas = document.createElement("canvas");
    canvas.width = w; canvas.height = hgt;
    const ctx = canvas.getContext("2d")!;
    ctx.drawImage(bmp, 0, 0, w, hgt);
    const data = ctx.getImageData(0, 0, w, hgt);
    const res = jsQR(data.data, w, hgt, { inversionAttempts: "attemptBoth" });
    if (!res?.data) return setError("qr", "No QR code found in that image. Try a tighter, sharper screenshot.");
    send({ type: "importText", text: res.data });
  } catch {
    setError("qr", "Couldn't read that image");
  }
}

document.addEventListener("paste", (e) => {
  if (state?.screen !== "unlocked") return;
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const it of Array.from(items)) {
    if (it.type.startsWith("image/")) {
      const f = it.getAsFile();
      if (f) {
        e.preventDefault();
        if (sheet?.kind !== "add" || sheet.tab !== "qr") openSheet({ kind: "add", tab: "qr" });
        decodeQrBlob(f);
      }
      return;
    }
  }
  // pasting an otpauth link anywhere outside an input adds it
  const text = e.clipboardData?.getData("text") || "";
  const tgt = e.target as HTMLElement;
  if (/^otpauth(-migration)?:\/\//i.test(text.trim()) && !tgt.closest("input,textarea")) {
    e.preventDefault();
    send({ type: "importText", text });
  }
});

function editSheet(id: string) {
  const e = entries().find((x) => x.id === id);
  if (!e) return sheetFrame("Edit", [h("p", {}, "Account not found")]);
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Save");
  const form = h("form", { class: "form", onSubmit: (ev: Event) => {
    ev.preventDefault();
    busy(btn, "update");
    send({ type: "update", id, patch: { issuer: val(form, "issuer"), account: val(form, "account") } });
  } },
    field("Issuer", h("input", { name: "issuer", value: e.issuer })),
    field("Account", h("input", { name: "account", value: e.account })),
    h("div", { class: "meta" },
      h("span", { class: "chip" }, e.type.toUpperCase()), h("span", { class: "chip" }, e.algorithm),
      h("span", { class: "chip" }, `${e.digits} digits`), !e.counterBased ? h("span", { class: "chip" }, `${e.period}s`) : null),
    errorBox("update"), btn,
    h("div", { class: "row" },
      h("button", { type: "button", class: "btn ghost", onClick: () => send({ type: "showQr", id }) }, icon("qr"), "Show QR"),
      h("button", { type: "button", class: "btn danger", onClick: () => send({ type: "delete", id }) }, icon("trash"), "Delete")));
  return sheetFrame("Edit account", [form]);
}

function menuItem(ic: string, title: string, sub: string, onClick: () => void, badge?: string) {
  return h("button", { class: "menu-item", onClick }, h("span", { class: "menu-icon" }, icon(ic)),
    h("span", { class: "menu-text" }, h("strong", {}, title), h("span", { class: "muted" }, sub)),
    badge ? h("span", { class: "badge warn" }, badge) : null, icon("chevron", "dim"));
}

function menuSheet() {
  if (state?.screen !== "unlocked") return h("div");
  const n = state.insights.length;
  return sheetFrame("Menu", [
    menuItem("download", "Backup & export", `Last backup: ${timeAgo(state.lastBackupAt)}`, () => openSheet({ kind: "backup" })),
    menuItem("upload", "Import", "Backup files, QR images, links", () => openSheet({ kind: "add", tab: "qr" })),
    menuItem("key", "Change master password", "Re-encrypts the vault", () => openSheet({ kind: "password" })),
    menuItem("shield", "Security", "Auto-lock, remember, hide codes", () => openSheet({ kind: "security" })),
    menuItem("alert", "Advisor", n ? `${n} suggestion${n > 1 ? "s" : ""}` : "All good", () => openSheet({ kind: "advisor" }), n ? String(n) : undefined),
    menuItem("clock", "Sync clock", `Offset ${state.offset >= 0 ? "+" : ""}${state.offset}s · fixes wrong codes`, () => send({ type: "syncClock" })),
    h("p", { class: "hint center" }, `${entries().length} account${entries().length === 1 ? "" : "s"} · Vault 2FA · no telemetry`),
  ]);
}

function backupSheet() {
  if (state?.screen !== "unlocked") return h("div");
  const folder = state.settings.autoBackupFolder;
  const btn = h("button", { class: "btn primary block", type: "submit" }, icon("download"), "Save encrypted backup…");
  const form = h("form", { class: "form", onSubmit: (ev: Event) => {
    ev.preventDefault();
    const pw = val(form, "bpw"), pw2 = val(form, "bpw2");
    if (pw.length < 8) return setError("exportEncrypted", "Use at least 8 characters");
    if (pw !== pw2) return setError("exportEncrypted", "Passwords don't match");
    busy(btn, "exportEncrypted");
    send({ type: "exportEncrypted", password: pw });
  } },
    field("Backup password", pwInput("bpw", "Can be your master password")),
    field("Confirm", pwInput("bpw2", "Repeat")), errorBox("exportEncrypted"), btn);
  return sheetFrame("Backup & export", [
    h("div", { class: "panel" },
      h("div", { class: "panel-head" }, icon("folder"), h("strong", {}, "Auto-backup")),
      h("p", { class: "muted" }, folder
        ? "After every change an encrypted copy is written here. It opens with your master password. Point this at a Dropbox / Drive / OneDrive folder for cloud sync."
        : "Pick a folder (e.g. inside Dropbox, Google Drive or OneDrive) and an encrypted copy is written after every change."),
      folder ? h("code", { class: "path" }, folder) : null,
      h("div", { class: "row" },
        h("button", { class: "btn ghost", onClick: () => send({ type: "chooseBackupFolder" }) }, folder ? "Change folder" : "Choose folder"),
        folder ? h("button", { class: "btn ghost", onClick: () => send({ type: "backupNow" }) }, "Back up now") : null)),
    h("div", { class: "panel" }, h("div", { class: "panel-head" }, icon("download"), h("strong", {}, "Export a backup file")), form),
    h("button", { class: "btn ghost danger-text block", onClick: () => send({ type: "exportPlain" }) }, "Export unencrypted otpauth links…"),
  ], () => openSheet({ kind: "menu" }));
}

function passwordSheet() {
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Change password");
  const meter = h("div", { class: "meter" }, h("div", { class: "meter-bar" }));
  const np = pwInput("new", "New password");
  np.querySelector("input")!.addEventListener("input", (e) => { meter.dataset.score = String(strength((e.target as HTMLInputElement).value).score); });
  const form = h("form", { class: "form", onSubmit: (ev: Event) => {
    ev.preventDefault();
    const o = val(form, "old"), n = val(form, "new"), n2 = val(form, "new2");
    if (n.length < 8) return setError("changePassword", "Use at least 8 characters");
    if (n !== n2) return setError("changePassword", "New passwords don't match");
    busy(btn, "changePassword");
    send({ type: "changePassword", oldPassword: o, newPassword: n });
  } },
    field("Current password", pwInput("old", "", true)), field("New password", np), meter,
    field("Confirm new password", pwInput("new2", "")), errorBox("changePassword"), btn);
  return sheetFrame("Change master password", [form], () => openSheet({ kind: "menu" }));
}

function toggleRow(title: string, sub: string, checked: boolean, onChange: (v: boolean) => void) {
  const inp = h("input", { type: "checkbox", checked, onChange: (e: Event) => onChange((e.target as HTMLInputElement).checked) }) as HTMLInputElement;
  inp.setAttribute("type", "checkbox");
  return h("label", { class: "toggle-row" }, h("span", { class: "menu-text" }, h("strong", {}, title), h("span", { class: "muted" }, sub)),
    h("span", { class: "switch" }, inp, h("span", { class: "slider" })));
}

function securitySheet() {
  if (state?.screen !== "unlocked") return h("div");
  const st = state.settings;
  const lock = h("select", { onChange: (e: Event) => send({ type: "setSetting", key: "autoLockMinutes", value: Number((e.target as HTMLSelectElement).value) }) },
    ...[1, 5, 15, 30, 60, 240, 0].map((m) => h("option", { value: m, selected: m === st.autoLockMinutes }, m === 0 ? "Never" : m < 60 ? `${m} min` : `${m / 60} h`)));
  return sheetFrame("Security", [
    h("label", { class: "toggle-row" }, h("span", { class: "menu-text" }, h("strong", {}, "Auto-lock after inactivity"),
      h("span", { class: "muted" }, "Vault always locks when VS Code restarts")), lock),
    toggleRow("Hide codes until hover", "Shoulder-surfing protection", st.hideCodes, (v) => send({ type: "setSetting", key: "hideCodes", value: v })),
    toggleRow("Remember on this machine", "Store the vault key in the OS keychain; opens without password", st.rememberOnThisMachine, (v) => send({ type: "setSetting", key: "rememberOnThisMachine", value: v })),
    h("p", { class: "hint" }, "Copied codes are cleared from the clipboard automatically (setting: vault2fa.clipboardClearSeconds)."),
  ], () => openSheet({ kind: "menu" }));
}

function advisorSheet() {
  if (state?.screen !== "unlocked") return h("div");
  const list = state.insights;
  const action = (i: Insight) =>
    i.id === "noBackup" || i.id === "staleBackup" ? h("button", { class: "btn ghost small", onClick: () => openSheet({ kind: "backup" }) }, "Back up")
    : i.id === "autoLockOff" || i.id === "rememberedKey" ? h("button", { class: "btn ghost small", onClick: () => openSheet({ kind: "security" }) }, "Fix")
    : null;
  return sheetFrame("Advisor", list.length ? list.map((i) => h("div", { class: `insight-card ${i.level}` },
    h("div", { class: "insight-head" }, icon("alert"), h("strong", {}, i.title), h("span", { class: `level ${i.level}` }, i.level)),
    h("p", { class: "muted" }, i.description),
    h("div", { class: "row" }, action(i), h("button", { class: "btn ghost small", onClick: () => send({ type: "ignoreInsight", id: i.id }) }, "Dismiss"))))
    : [h("div", { class: "empty small" }, h("div", { class: "empty-orb ok" }, icon("shield")), h("p", {}, "Everything looks good."))],
  () => openSheet({ kind: "menu" }));
}

function qrSheet(label: string, svg: string) {
  const box = h("div", { class: "qr-box" });
  box.innerHTML = svg;
  return sheetFrame("QR code", [h("p", { class: "center" }, h("strong", {}, label)), box,
    h("div", { class: "notice" }, icon("alert"), h("span", {}, "Anyone who scans this can generate your codes. Close it when done."))]);
}

function importPasswordSheet(text: string, format: string) {
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Decrypt & import");
  const form = h("form", { class: "form", onSubmit: (ev: Event) => {
    ev.preventDefault();
    busy(btn, "importText");
    send({ type: "importText", text, password: val(form, "ipw") });
  } }, h("p", { class: "muted" }, `This ${format === "vault2fa" ? "Vault 2FA" : format === "chrome" ? "Chrome Authenticator" : format} backup is encrypted.`),
    field("Backup password", pwInput("ipw", "", true)), errorBox("importText"), btn);
  return sheetFrame("Encrypted backup", [form]);
}

// ---------- root render ----------
function render() {
  const app = $("#app")!;
  if (!state) return;
  const key = state.screen;
  if (key !== lastScreen || key !== "unlocked") {
    lastScreen = key;
    app.replaceChildren(
      key === "setup" ? renderSetup() : key === "locked" ? renderLocked(state.throttledMs, state.remember) : renderUnlockedShell(),
    );
    if (key !== "unlocked") { sheet = null; codes = {}; lastCounters = {}; }
  }
  if (state.screen === "unlocked") {
    codes = Object.fromEntries(state.entries.map((e) => [e.id, e.code]));
    renderInsights();
    renderList();
    if (sheet?.kind === "menu" || sheet?.kind === "security" || sheet?.kind === "advisor" || sheet?.kind === "backup") renderSheet();
    if (sheet?.kind === "edit" && !state.entries.some((e) => e.id === (sheet as { id: string }).id)) closeSheet();
  }
}

window.addEventListener("message", (ev: MessageEvent<HostMsg>) => {
  const m = ev.data;
  switch (m.type) {
    case "state": state = m.state; render(); break;
    case "codes":
      codes = { ...codes, ...m.codes };
      document.querySelectorAll<HTMLElement>("[data-code]").forEach((el) => {
        const c = codes[el.dataset.code!];
        if (c !== undefined) { el.textContent = c ? formatCode(c) : "Invalid secret"; el.classList.add("flip"); setTimeout(() => el.classList.remove("flip"), 400); }
      });
      break;
    case "toast": toast(m.text, m.kind); break;
    case "error": setError(m.form, m.text); break;
    case "done": setError(m.form, ""); closeSheet(); break;
    case "qr": openSheet({ kind: "qr", label: m.label, svg: m.svg }); break;
    case "needPassword": openSheet({ kind: "importPassword", text: m.text, format: m.format }); break;
  }
});

let lastAct = 0;
for (const evName of ["click", "keydown"]) {
  window.addEventListener(evName, () => {
    if (Date.now() - lastAct > 20_000) { lastAct = Date.now(); send({ type: "activity" }); }
  }, true);
}
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && sheet) closeSheet();
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") { e.preventDefault(); ($(".search") as HTMLInputElement | null)?.focus(); }
});

send({ type: "ready" });
