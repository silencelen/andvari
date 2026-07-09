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
  // Scaffold proof-of-life; TODO: on field focus, ask the SW for matches for location.host and
  // render an inline chip / dropdown to fill, then a "Save to andvari?" prompt on submit.
  console.debug("[andvari] login form detected on", location.host, "username field:", Boolean(fields.username));
}
