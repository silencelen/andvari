/**
 * Content script — detects login forms and (TODO) offers fill/save. The browser equivalent of the
 * Android FieldClassifier: DOM signals (input type, autocomplete tokens, name/id keywords) instead
 * of an AssistStructure. Host matching reuses the SAME idea as core UriMatch (host / registrable
 * domain). Talks to the SW for matching logins; the SW holds the vault key, never the page.
 */
interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

function findLoginFields(): LoginFields {
  const password = document.querySelector<HTMLInputElement>('input[type="password"]');
  let username: HTMLInputElement | null = null;
  if (password) {
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    const pi = inputs.indexOf(password);
    // Nearest preceding text/email input = the username (DOM-order heuristic). TODO: prefer
    // autocomplete="username"/"email" and name/id keywords, mirroring the Android classifier rules.
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

const fields = findLoginFields();
if (fields.password) {
  // On focusing a login field, ask the SW (which holds the decrypted vault) for logins matching this
  // host. Proves the end-to-end pipeline: content → SW → decrypted items → host match. TODO: render an
  // inline chip/dropdown to CHOOSE + a "reveal" message that returns the chosen password to fill, then
  // a "Save to andvari?" prompt on submit (mirrors the Android save flow).
  const onFocus = async (): Promise<void> => {
    try {
      const r = (await chrome.runtime.sendMessage({ type: "matches", host: location.host })) as
        | { matches?: { itemId: string; name: string; username: string | null }[] }
        | undefined;
      const matches = r?.matches ?? [];
      console.debug("[andvari]", matches.length, "login match(es) for", location.host, matches.map((m) => m.name));
    } catch {
      /* SW asleep / locked — the popup handles unlock */
    }
  };
  fields.username?.addEventListener("focus", onFocus, { once: true });
  fields.password.addEventListener("focus", onFocus, { once: true });
}
