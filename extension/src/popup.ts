/**
 * Popup — status + a server smoke test for the scaffold. TODO: a real unlock form (master password
 * → prelogin for kdfParams+salt → sendMessage {type:"unlock"}), then a vault/item list. External
 * script only (MV3 CSP forbids inline), event listeners (no inline handlers).
 */
const el = (id: string): HTMLElement => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`#${id} missing`);
  return e;
};

async function refresh(): Promise<void> {
  const s = (await chrome.runtime.sendMessage({ type: "status" })) as { unlocked?: boolean } | undefined;
  el("status").textContent = s?.unlocked ? "Unlocked" : "Locked";
}

el("ping").addEventListener("click", async () => {
  el("msg").textContent = "…";
  try {
    const r = (await chrome.runtime.sendMessage({ type: "ping" })) as
      | { ok: boolean; serverTime?: number; error?: string }
      | undefined;
    el("msg").textContent = r?.ok ? `server reachable (t=${r.serverTime})` : `error: ${r?.error ?? "no response"}`;
  } catch (e) {
    el("msg").textContent = String(e);
  }
});

void refresh();
