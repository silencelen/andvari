/**
 * Content script — the in-page autofill UI: a fill dropdown on login fields + a "Save to andvari?"
 * banner on submit. The SW holds the decrypted vault and does all crypto; this only renders UI,
 * requests matches/reveal, and sets field values. A secret reaches the page ONLY on an explicit user
 * fill (the value must enter the field to autofill) — mirrors the platform autofill trust model.
 *
 * (Styling uses inline styles for the spike; strict-CSP sites may need a shadow-root + injected
 * stylesheet — TODO(extension).)
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
  // Fire the events page frameworks listen for so they register the change.
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
  box.style.cssText =
    `position:absolute;z-index:2147483647;left:${rect.left + window.scrollX}px;top:${rect.bottom + window.scrollY}px;` +
    `min-width:${Math.max(rect.width, 220)}px;background:#fff;border:1px solid #ccc;border-radius:6px;` +
    `box-shadow:0 4px 16px rgba(0,0,0,.18);font:13px system-ui,sans-serif;color:#111;overflow:hidden;`;
  for (const m of matches) {
    const row = document.createElement("div");
    row.style.cssText = "padding:8px 10px;cursor:pointer;border-bottom:1px solid #eee;";
    row.textContent = m.username ? `${m.name} · ${m.username}` : m.name;
    row.addEventListener("mousedown", (e) => {
      e.preventDefault(); // keep focus off the row so the field stays targetable
      void fillMatch(m.itemId, fields);
    });
    box.appendChild(row);
  }
  const brand = document.createElement("div");
  brand.style.cssText = "padding:4px 10px;font-size:11px;color:#888;";
  brand.textContent = "andvari";
  box.appendChild(brand);
  document.body.appendChild(box);
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
  bar.style.cssText =
    "position:fixed;z-index:2147483647;top:12px;right:12px;background:#fff;border:1px solid #ccc;border-radius:8px;" +
    "box-shadow:0 4px 16px rgba(0,0,0,.2);padding:12px;font:13px system-ui,sans-serif;color:#111;max-width:300px;";
  const msg = document.createElement("div");
  msg.textContent = `Save this login for ${location.host} to andvari?`;
  const save = document.createElement("button");
  save.textContent = "Save";
  save.style.marginRight = "8px";
  const no = document.createElement("button");
  no.textContent = "Not now";
  save.addEventListener("click", () => {
    void chrome.runtime.sendMessage({ type: "save", url: location.href, username, password });
    bar.remove();
  });
  no.addEventListener("click", () => bar.remove());
  const row = document.createElement("div");
  row.style.marginTop = "8px";
  row.append(save, no);
  bar.append(msg, row);
  document.body.appendChild(bar);
  setTimeout(() => bar.remove(), 20_000);
}

const fields = findLoginFields();
if (fields.password) {
  const anchor = fields.username ?? fields.password;
  anchor.addEventListener("focus", () => void showDropdown(anchor, fields));
  document.addEventListener("click", (e) => {
    if (dropdown && !dropdown.contains(e.target as Node)) closeDropdown();
  });
  // Offer to save on submit — form submit, plus Enter in the password field (SPAs often skip forms).
  fields.password.form?.addEventListener("submit", () => void maybeOfferSave(fields));
  fields.password.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void maybeOfferSave(fields);
  });
}
