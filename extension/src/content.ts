/**
 * Content script — the in-page autofill UI: a fill dropdown on login fields + a "Save to andvari?"
 * banner. The SW holds the decrypted vault and does all crypto; this only renders UI, requests
 * matches/reveal, and sets field values. A secret reaches the page ONLY on an explicit user fill.
 *
 * Strict-CSP hardening: all UI lives in a CLOSED shadow root, styled by a constructed CSSStyleSheet
 * via adoptedStyleSheets — encapsulated from the page's CSS AND immune to the page's `style-src`
 * (unlike inline <style>/style="" attributes). Dynamic position is set via CSSOM (el.style.*), which
 * is not gated by CSP. So the UI renders identically on github.com, banks, and other locked-down sites.
 */
interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}
interface Match {
  itemId: string;
  name: string;
  username: string | null;
}

const UI_CSS = `
:host { all: initial; }
.dropdown { position: fixed; min-width: 220px; max-width: 360px; background: #fff; border: 1px solid #c9c9cf;
  border-radius: 6px; box-shadow: 0 6px 20px rgba(0,0,0,.18); font: 13px system-ui, sans-serif; color: #16161a;
  overflow: hidden; }
.dropdown .row { padding: 9px 11px; cursor: pointer; border-bottom: 1px solid #eee; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; }
.dropdown .row:hover { background: #f2f2f5; }
.brand { padding: 4px 11px; font-size: 11px; color: #8a8a92; }
.banner { position: fixed; top: 14px; right: 14px; max-width: 300px; background: #fff; border: 1px solid #c9c9cf;
  border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,.2); padding: 13px; font: 13px system-ui, sans-serif;
  color: #16161a; }
.banner .actions { margin-top: 10px; display: flex; gap: 8px; }
.banner button { font: 13px system-ui, sans-serif; padding: 5px 12px; border-radius: 6px; border: 1px solid #c9c9cf;
  background: #f6f6f8; cursor: pointer; }
.banner button.primary { background: #16161a; color: #fff; border-color: #16161a; }
`;

let shadow: ShadowRoot | null = null;
let hostEl: HTMLElement | null = null;
function ui(): ShadowRoot {
  if (shadow) return shadow;
  hostEl = document.createElement("div");
  (document.documentElement || document.body).appendChild(hostEl);
  const root = hostEl.attachShadow({ mode: "closed" });
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(UI_CSS);
  root.adoptedStyleSheets = [sheet];
  shadow = root;
  return root;
}

function findLoginFields(): LoginFields {
  const password = document.querySelector<HTMLInputElement>('input[type="password"]');
  let username: HTMLInputElement | null = null;
  if (password) {
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    const pi = inputs.indexOf(password);
    for (let i = pi - 1; i >= 0; i--) {
      const t = inputs[i].type;
      if (t === "text" || t === "email" || t === "tel") {
        username = inputs[i];
        break;
      }
    }
  }
  return { username, password };
}

function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

let dropdown: HTMLElement | null = null;
function closeDropdown(): void {
  dropdown?.remove();
  dropdown = null;
}

async function fillMatch(itemId: string, fields: LoginFields): Promise<void> {
  const r = (await chrome.runtime.sendMessage({ type: "reveal", itemId })) as
    | { secret?: { username: string | null; password: string | null } }
    | undefined;
  const s = r?.secret;
  if (!s) return;
  if (fields.username && s.username) setValue(fields.username, s.username);
  if (fields.password && s.password) setValue(fields.password, s.password);
  closeDropdown();
}

async function showDropdown(anchor: HTMLInputElement, fields: LoginFields): Promise<void> {
  const r = (await chrome.runtime.sendMessage({ type: "matches", host: location.host })) as { matches?: Match[] } | undefined;
  const matches = r?.matches ?? [];
  if (matches.length === 0) return;
  closeDropdown();
  const rect = anchor.getBoundingClientRect();
  const box = document.createElement("div");
  box.className = "dropdown";
  box.style.left = `${rect.left}px`; // CSSOM (not CSP-gated); position:fixed → viewport coords
  box.style.top = `${rect.bottom}px`;
  box.style.width = `${Math.max(rect.width, 220)}px`;
  for (const m of matches) {
    const row = document.createElement("div");
    row.className = "row";
    row.textContent = m.username ? `${m.name} · ${m.username}` : m.name;
    row.addEventListener("mousedown", (e) => {
      e.preventDefault(); // keep focus on the field so it stays fillable
      void fillMatch(m.itemId, fields);
    });
    box.appendChild(row);
  }
  const brand = document.createElement("div");
  brand.className = "brand";
  brand.textContent = "andvari";
  box.appendChild(brand);
  ui().appendChild(box);
  dropdown = box;
}

async function maybeOfferSave(fields: LoginFields): Promise<void> {
  const username = fields.username?.value ?? "";
  const password = fields.password?.value ?? "";
  if (!password) return;
  const r = (await chrome.runtime.sendMessage({ type: "matches", host: location.host })) as { matches?: Match[] } | undefined;
  if ((r?.matches ?? []).some((m) => m.username === username)) return; // andvari already has this login
  showSaveBanner(username, password);
}

function showSaveBanner(username: string, password: string): void {
  const bar = document.createElement("div");
  bar.className = "banner";
  const msg = document.createElement("div");
  msg.textContent = `Save this login for ${location.host} to andvari?`;
  const save = document.createElement("button");
  save.className = "primary";
  save.textContent = "Save";
  const no = document.createElement("button");
  no.textContent = "Not now";
  save.addEventListener("click", () => {
    void chrome.runtime.sendMessage({ type: "save", url: location.href, username, password });
    bar.remove();
  });
  no.addEventListener("click", () => bar.remove());
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(save, no);
  bar.append(msg, actions);
  ui().appendChild(bar);
  setTimeout(() => bar.remove(), 20_000);
}

const fields = findLoginFields();
if (fields.password) {
  const anchor = fields.username ?? fields.password;
  anchor.addEventListener("focus", () => void showDropdown(anchor, fields));
  // Close on a mousedown outside the dropdown — composedPath() pierces the shadow boundary.
  document.addEventListener("mousedown", (e) => {
    if (dropdown && !e.composedPath().includes(dropdown)) closeDropdown();
  });
  fields.password.form?.addEventListener("submit", () => void maybeOfferSave(fields));
  fields.password.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void maybeOfferSave(fields);
  });
}
