/**
 * Popup — unlock form (email + master password → SW), unlocked status + Lock, and a server smoke
 * test. The SW does the crypto + holds the vault key; the popup only messages it. External script
 * only (MV3 CSP forbids inline), event listeners (no inline handlers).
 */
const el = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`#${id} missing`);
  return e as T;
};

async function refresh(): Promise<void> {
  const s = (await chrome.runtime.sendMessage({ type: "status" })) as { unlocked?: boolean; count?: number } | undefined;
  const unlocked = s?.unlocked === true;
  el("locked").style.display = unlocked ? "none" : "block";
  el("unlocked").style.display = unlocked ? "block" : "none";
  if (unlocked) el("count").textContent = `Unlocked · ${s?.count ?? 0} logins`;
}

el<HTMLButtonElement>("unlock").addEventListener("click", async () => {
  const email = el<HTMLInputElement>("email").value.trim();
  const pw = el<HTMLInputElement>("password");
  if (!email || !pw.value) return;
  el("msg").textContent = "Unlocking… (this takes a few seconds)";
  el<HTMLButtonElement>("unlock").disabled = true;
  try {
    const r = (await chrome.runtime.sendMessage({ type: "unlock", email, password: pw.value })) as
      | { ok: boolean; error?: string }
      | undefined;
    el("msg").textContent = r?.ok ? "" : `Couldn't unlock: ${r?.error ?? "no response"}`;
    pw.value = "";
    await refresh();
  } catch (e) {
    el("msg").textContent = String(e);
  } finally {
    el<HTMLButtonElement>("unlock").disabled = false;
  }
});

el("lock").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "lock" });
  await refresh();
});

el("ping").addEventListener("click", async () => {
  el("msg").textContent = "…";
  const r = (await chrome.runtime.sendMessage({ type: "ping" })) as
    | { ok: boolean; serverTime?: number; error?: string }
    | undefined;
  el("msg").textContent = r?.ok ? `server reachable (t=${r.serverTime})` : `error: ${r?.error ?? "no response"}`;
});

void refresh();
