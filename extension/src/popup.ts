/**
 * Popup — the themed vault surface. Locked: email + master password → SW `unlock` (the ~6 s
 * Argon2id shows the animated "Unsealing…" state). Unlocked: current-site matches + search-all
 * rows — a row click fills via the SW's one-shot grant (`fillFromPopup`); hover copy buttons
 * (password via explicit `reveal`, written straight to the clipboard, never rendered); live
 * TOTP chips re-polled each second. The SW holds all key material — this page only messages it.
 * External module only (MV3 CSP forbids inline); vault strings land via textContent only.
 */
import { send, type MatchItem, type Req, type Res } from "./messages";

const SERVER_URL = "https://andvari.taila2dff2.ts.net";
const FLASH_MS = 1200;
const TOTP_PERIOD_S = 30; // ring denominator (web Vault parity)

const el = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`#${id} missing`);
  return e as T;
};

/** send() that survives a mid-flight SW restart ("receiving end does not exist") as undefined. */
async function ask<T extends Req["type"]>(req: Extract<Req, { type: T }>): Promise<Res<T> | undefined> {
  try {
    return await send(req);
  } catch {
    return undefined;
  }
}

let tabHost: string | null = null;
let totpTimer: number | undefined;
let searchTimer: number | undefined;
let searchSeq = 0;

function showMsg(kind: "err" | "info", text: string): void {
  const m = el("msg");
  m.className = `msg ${kind}`;
  m.textContent = text;
  m.hidden = false;
}

function clearMsg(): void {
  const m = el("msg");
  m.textContent = "";
  m.hidden = true;
}

function setConn(ok: boolean): void {
  const dot = el("conn");
  dot.className = `dot ${ok ? "on" : "off"}`;
  dot.title = ok ? "server reachable" : "server unreachable";
}

function showView(unlocked: boolean): void {
  el("locked").hidden = unlocked;
  el("unlocked").hidden = !unlocked;
  el("lock").hidden = !unlocked;
  el("count").hidden = !unlocked;
  if (!unlocked) {
    stopTotp();
    // Drop rendered vault rows/codes on lock — nothing lingers in the DOM.
    el("site-list").replaceChildren();
    el("all-list").replaceChildren();
    el<HTMLInputElement>("search").value = "";
    el("gen-pass").textContent = "";
    el("generator").hidden = true;
    el("gen-toggle").classList.remove("on");
  }
}

async function refresh(): Promise<void> {
  const s = await ask({ type: "status" });
  if (!s) {
    showView(false);
    showMsg("err", "Extension backend not responding — try reloading the extension.");
    return;
  }
  showView(s.unlocked);
  if (s.unlocked) {
    await loadUnlocked();
    return;
  }
  const email = el<HTMLInputElement>("email");
  if (!email.value) {
    const remembered = s.email ?? (await rememberedEmail());
    if (remembered) email.value = remembered;
  }
  (email.value ? el("password") : email).focus();
}

/** Email is deliberately non-secret (remembered for convenience) — the ZK line is the master
 *  password and keys, which never touch chrome.storage.local. */
async function rememberedEmail(): Promise<string | null> {
  try {
    const st = (await chrome.storage.local.get("lastEmail")) as Record<string, unknown>;
    const v = st["lastEmail"];
    return typeof v === "string" && v ? v : null;
  } catch {
    return null;
  }
}

function relocked(): void {
  showView(false);
  showMsg("info", "Session locked — unlock to continue.");
}

async function loadUnlocked(): Promise<void> {
  const host = await activeTabHost();
  tabHost = host;
  const siteLabel = el("site-label");
  const siteList = el("site-list");
  if (host) {
    siteLabel.hidden = false;
    siteList.hidden = false;
    siteLabel.textContent = `This site — ${host}`;
    const r = await ask({ type: "matches", host });
    if (!r || r.locked) return relocked();
    renderList(siteList, r.matches, `No login saved for ${host}`, true);
  } else {
    // No usable page URL (chrome://, new tab, detached popup) — nothing to match against.
    siteLabel.hidden = true;
    siteList.hidden = true;
  }
  const all = await ask({ type: "allItems" });
  if (!all || all.locked) return relocked();
  const n = all.items.length;
  el("count").textContent = `${n} login${n === 1 ? "" : "s"} in the hoard`;
  renderList(el("all-list"), all.items, "The hoard is empty");
  startTotp();
  el<HTMLInputElement>("search").focus();
}

/** activeTab (granted by opening the popup) exposes the page URL on http/https only. */
async function activeTabHost(): Promise<string | null> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const u = new URL(tabs[0]?.url ?? "");
    return (u.protocol === "https:" || u.protocol === "http:") && u.hostname ? u.hostname : null;
  } catch {
    return null;
  }
}

function renderList(list: HTMLElement, items: MatchItem[], emptyText: string, slim = false): void {
  list.replaceChildren();
  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = slim ? "empty slim" : "empty";
    if (!slim) {
      const sigil = document.createElement("div");
      sigil.className = "sigil";
      sigil.textContent = "ᛅ";
      empty.append(sigil);
    }
    empty.append(emptyText);
    list.append(empty);
    return;
  }
  for (const it of items) list.append(row(it));
}

/** Row = fill on click (nested copy/TOTP buttons stop propagation, so the row can't be a
 *  <button> itself — divs with button semantics instead). */
function row(it: MatchItem): HTMLElement {
  const r = document.createElement("div");
  r.className = "item";
  r.setAttribute("role", "button");
  r.tabIndex = 0;
  r.title = "Fill on this page";

  const glyph = document.createElement("span");
  glyph.className = "glyph";
  glyph.textContent = (it.name.trim().charAt(0) || "ᛅ").toUpperCase();

  const body = document.createElement("div");
  body.className = "body";
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = it.name;
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = it.username ?? "no username";
  body.append(name, sub);

  r.append(glyph, body);
  if (it.hasTotp) r.append(totpChip(it.itemId));

  const acts = document.createElement("span");
  acts.className = "acts";
  if (it.username) acts.append(actBtn("user", "Copy username", (btn) => void copyUsername(it, btn)));
  acts.append(actBtn("pass", "Copy password", (btn) => void copyPassword(it, btn)));
  r.append(acts);

  const fill = () => void fillItem(it.itemId);
  r.addEventListener("click", fill);
  r.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fill();
    }
  });
  return r;
}

function actBtn(label: string, title: string, onClick: (btn: HTMLButtonElement) => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "fill-btn";
  b.textContent = label;
  b.title = title;
  b.dataset["label"] = label;
  b.addEventListener("click", (e) => {
    e.stopPropagation(); // the row itself fills
    onClick(b);
  });
  return b;
}

function flash(btn: HTMLElement): void {
  btn.textContent = "✓";
  btn.classList.add("did");
  window.setTimeout(() => {
    btn.textContent = btn.dataset["label"] ?? "";
    btn.classList.remove("did");
  }, FLASH_MS);
}

async function toClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    showMsg("err", `Clipboard: ${String(e)}`);
    return false;
  }
}

async function fillItem(itemId: string): Promise<void> {
  const r = await ask({ type: "fillFromPopup", itemId });
  if (r?.ok) {
    window.close(); // the fill lands in the page
  } else {
    showMsg("err", r?.error ?? "Couldn't reach the page — reload the tab and retry.");
  }
}

/** The list payload already carries the username (safe subset) — no reveal round-trip. */
async function copyUsername(it: MatchItem, btn: HTMLElement): Promise<void> {
  if (it.username && (await toClipboard(it.username))) flash(btn);
}

async function copyPassword(it: MatchItem, btn: HTMLElement): Promise<void> {
  const r = await ask({ type: "reveal", itemId: it.itemId, host: tabHost ?? "", explicit: true });
  if (!r?.ok || r.secret?.password == null) {
    showMsg("err", r?.error ?? "No password on this item.");
    return;
  }
  if (await toClipboard(r.secret.password)) flash(btn); // just the one field, straight to clipboard
}

/* ---- live TOTP chips: 1 s re-poll while the unlocked view is up; click = copy ---- */

function totpChip(itemId: string): HTMLElement {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.className = "totp-chip";
  chip.dataset["item"] = itemId;
  chip.title = "Copy one-time code";
  const ring = document.createElement("span");
  ring.className = "ring";
  const code = document.createElement("span");
  code.className = "code";
  code.textContent = "······";
  chip.append(ring, code);
  chip.addEventListener("click", (e) => {
    e.stopPropagation();
    void copyTotp(itemId, code);
  });
  return chip;
}

async function copyTotp(itemId: string, codeEl: HTMLElement): Promise<void> {
  const r = await ask({ type: "totp", itemId });
  if (!r?.ok || !r.code) return;
  if (await toClipboard(r.code)) {
    codeEl.textContent = "copied";
    codeEl.dataset["hold"] = String(Date.now() + FLASH_MS); // ticker restores the live code after
  }
}

function startTotp(): void {
  stopTotp();
  totpTimer = window.setInterval(() => void tickTotp(), 1000);
  void tickTotp();
}

function stopTotp(): void {
  if (totpTimer !== undefined) {
    window.clearInterval(totpTimer);
    totpTimer = undefined;
  }
}

async function tickTotp(): Promise<void> {
  // The 1 s ticker is also the popup's liveness check: if the session locked while the popup was
  // open (idle autolock, or a Lock from another surface), flip to the locked view instead of
  // leaving a stale — and now unusable — vault list on screen. Distinct from a per-chip {ok:false}
  // (a malformed TOTP), which must NOT relock the whole popup.
  const st = await ask({ type: "status" });
  if (!st) return; // SW mid-restart — retry next tick
  if (!st.unlocked) {
    relocked();
    return;
  }
  for (const chip of document.querySelectorAll<HTMLElement>(".totp-chip")) {
    const itemId = chip.dataset["item"];
    const code = chip.querySelector<HTMLElement>(".code");
    const ring = chip.querySelector<HTMLElement>(".ring");
    if (!itemId || !code || !ring) continue;
    const r = await ask({ type: "totp", itemId });
    if (r?.ok && r.code) {
      if (Date.now() >= Number(code.dataset["hold"] ?? 0)) {
        code.textContent = r.code.replace(/^(\d{3})(\d{3})$/, "$1 $2");
      }
      ring.style.setProperty("--p", String(((r.secondsLeft ?? 0) / TOTP_PERIOD_S) * 100));
    } else {
      chip.hidden = true; // locked mid-poll / item no longer carries a code
    }
  }
}

/* ---- search-all (debounced; out-of-order responses dropped) ---- */

async function runSearch(): Promise<void> {
  const q = el<HTMLInputElement>("search").value.trim();
  const seq = ++searchSeq;
  const r = await ask({ type: "allItems", query: q || undefined });
  if (seq !== searchSeq) return; // a newer query superseded this response
  if (!r || r.locked) return relocked();
  renderList(el("all-list"), r.items, q ? `Nothing in the hoard matches “${q}”` : "The hoard is empty");
}

el<HTMLInputElement>("search").addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => void runSearch(), 150);
});

/* ---- generator: one collapsible section; every Regenerate is a fresh SW `generate` ---- */

async function regenerate(): Promise<void> {
  const r = await ask({ type: "generate" });
  el("gen-pass").textContent = r?.password ?? "";
}

el("gen-toggle").addEventListener("click", () => {
  const g = el("generator");
  g.hidden = !g.hidden;
  el("gen-toggle").classList.toggle("on", !g.hidden);
  if (!g.hidden && !el("gen-pass").textContent) void regenerate();
});

el("gen-again").addEventListener("click", () => void regenerate());

el("gen-pass").addEventListener("click", async () => {
  const pw = el("gen-pass").textContent;
  if (pw && (await toClipboard(pw))) {
    const f = el("gen-flash");
    f.hidden = false;
    window.setTimeout(() => {
      f.hidden = true;
    }, FLASH_MS);
  }
});

/* ---- unlock ---- */

function setUnsealing(busy: boolean): void {
  const btn = el<HTMLButtonElement>("unlock");
  btn.disabled = busy;
  btn.textContent = busy ? "Unsealing…" : "Unlock";
  el("kdf").hidden = !busy;
}

function unlockError(raw: string | undefined): string {
  if (!raw) return "Couldn't unlock: no response from the extension";
  if (/fetch|network/i.test(raw)) return `Can't reach the server — is Tailscale connected? (${raw})`;
  return `Couldn't unlock: ${raw}`;
}

async function unlock(): Promise<void> {
  if (el<HTMLButtonElement>("unlock").disabled) return; // Enter while a KDF is already running
  const email = el<HTMLInputElement>("email").value.trim();
  const pw = el<HTMLInputElement>("password");
  if (!email || !pw.value) return;
  clearMsg();
  setUnsealing(true);
  try {
    const r = await ask({ type: "unlock", email, password: pw.value });
    if (r?.ok) {
      pw.value = "";
      try {
        await chrome.storage.local.set({ lastEmail: email }); // the email only — never the password
      } catch {
        /* remembering is best-effort */
      }
      await refresh();
    } else {
      showMsg("err", unlockError(r?.error));
      pw.select();
    }
  } finally {
    setUnsealing(false);
  }
}

el<HTMLButtonElement>("unlock").addEventListener("click", () => void unlock());
el<HTMLInputElement>("email").addEventListener("keydown", (e) => {
  if (e.key === "Enter") el("password").focus();
});
el<HTMLInputElement>("password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") void unlock();
});

/* ---- footer ---- */

el("lock").addEventListener("click", async () => {
  await ask({ type: "lock" });
  clearMsg();
  await refresh();
});

el("open-vault").addEventListener("click", () => {
  void chrome.tabs.create({ url: SERVER_URL });
  window.close();
});

el("ping").addEventListener("click", async () => {
  showMsg("info", "…");
  const r = await ask({ type: "ping" });
  setConn(r?.ok === true);
  if (r?.ok) showMsg("info", `server reachable (t=${r.serverTime})`);
  else showMsg("err", `server: ${r?.error ?? "no response"}`);
});

void refresh();
// Passive connectivity dot — quiet ping on open, result only in the header dot.
void ask({ type: "ping" }).then((r) => setConn(r?.ok === true));
