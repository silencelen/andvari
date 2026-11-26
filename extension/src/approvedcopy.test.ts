// node --test (see version.test.ts). The owner's approved wording (copy page 2026-11-15, all 28 entries approved)
// where the extension shows it: pinned word for word, because the words are his and a change here is one he did not
// approve. Entries 8, 10, 11, 12, 13 and 15 apply here; the others name screens the extension does not have.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  CARD_MOVE_NOT_FOLLOWED_TITLE,
  CARD_RECORD_DAMAGED_TITLE,
  CARD_REFUSED_KEPT,
  cardRecordDamagedCopy,
  chooseServerCopy,
  chooseServerMessage,
  fillApproved,
  GATE_TITLE_KIND_CHANGE,
  LINK_REQUIRED_CANNOT_LINK_TITLE,
  linkRequiredCopy,
  moveNotFollowedCopy,
  SERVER_MOVED_UPDATE,
  unlockErrorCopy,
  unlockErrorMessage,
} from "./errors.ts";
import { messageBlocks, renderBlocks, setLiveMsgBlocks } from "./livemsg.ts";

/** A document stand-in that records every element made and every write to it. It has no innerHTML: a write of markup
 *  would land on a property nothing renders, and the test would see the text missing. */
function fakeHost() {
  const made: { tag: string; className: string; textContent: string | null }[] = [];
  let children: unknown[] = [];
  const writes: string[] = [];
  const host = {
    hidden: true,
    textContent: null as string | null,
    className: "",
    setAttribute(name: string, value: string) {
      writes.push(`${name}=${value}`);
    },
    ownerDocument: {
      createElement(tag: "strong" | "p") {
        const e = { tag, className: "", textContent: null as string | null };
        made.push(e);
        return e;
      },
    },
    replaceChildren(...nodes: unknown[]) {
      writes.push(`children=${nodes.length}`);
      children = nodes;
    },
  };
  return { host, made, writes, children: () => children };
}

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf-8");

test("entry 11: a newer card that does not verify", () => {
  assert.equal(
    CARD_REFUSED_KEPT,
    "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.",
  );
  assert.ok(read("./popup.ts").includes('else if (n.kind === "invalid") text.textContent = CARD_REFUSED_KEPT;'));
});

test("entry 12: a damaged record, in the popup's stop and on the options page", () => {
  assert.equal(CARD_RECORD_DAMAGED_TITLE, "andvari can't read its record of this server");
  assert.equal(
    cardRecordDamagedCopy("https://a.example"),
    "The record this device keeps of the identity of https://a.example is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.\n" +
      "If you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected.",
  );
  const popup = read("./popup.ts");
  assert.ok(popup.includes(': CARD_RECORD_DAMAGED_TITLE;'));
  // Both paragraphs reach the screen as two paragraphs, in the popup's stop and on the options page.
  assert.ok(popup.includes("else renderBlocks(el(\"confirm-server-body\"), messageBlocks(null, cardRecordDamagedCopy(block.origin)));"));
  const options = read("./options.ts");
  assert.ok(options.includes('serverStopHeading.textContent = stop?.kind === "pin_damaged" ? CARD_RECORD_DAMAGED_TITLE'));
  assert.ok(options.includes("renderBlocks(serverStopBody, messageBlocks(null, cardRecordDamagedCopy(stop.origin)))"));
  const blocks = messageBlocks(null, cardRecordDamagedCopy("https://a.example"));
  assert.equal(blocks.length, 2);
  assert.ok(blocks.every((b) => b.tag === "p"));
  assert.ok(blocks[0]!.text.startsWith("The record this device keeps") && blocks[1]!.text.startsWith("If you went back"));
  // The containers are block elements a paragraph may sit in.
  assert.ok(read("../popup.html").includes('<div id="confirm-server-body" class="confirm-server-body"></div>'));
  assert.ok(read("../options.html").includes('<div id="server-stop-body" class="gate-body"></div>'));
});

test("entry 13: a move this browser does not follow names the new address, under its title", () => {
  assert.equal(CARD_MOVE_NOT_FOLLOWED_TITLE, "andvari didn't follow this move");
  assert.equal(
    moveNotFollowedCopy("https://new.example"),
    "This device already knows https://new.example as a server, and a move never replaces a server this device already knows. Nothing changed. If you set it up on this device yourself, as this server's new address, sign out and sign in there. If you didn't, ask this server's operator what happened.",
  );
  assert.ok(read("./popup.ts").includes('if (r?.code === "pin_conflict" && to) showMsg("err", moveNotFollowedCopy(to), CARD_MOVE_NOT_FOLLOWED_TITLE);'));
});

test("entry 15: link_required names the account, under its title, at both sign-in steps", () => {
  const said =
    "sam@example.com has “New devices must be linked” turned on, and andvari in a browser can't be linked. Your master password was right. To sign in here, open andvari on one of your devices → Settings → Your devices, and turn that setting off. You can turn it on again once this browser has signed in.";
  assert.equal(linkRequiredCopy("sam@example.com"), said);
  assert.equal(unlockErrorCopy("link_required", "sam@example.com"), said);
  assert.equal(LINK_REQUIRED_CANNOT_LINK_TITLE, "This account only allows linked devices");
  assert.deepEqual(unlockErrorMessage("link_required", "sam@example.com"), { title: "This account only allows linked devices", body: said });
  assert.deepEqual(unlockErrorMessage("bad_credentials"), { title: null, body: "Wrong email or master password." });
  const popup = read("./popup.ts");
  assert.ok(popup.includes('showTitled("err", unlockErrorMessage(r?.code, email));'));
  assert.ok(popup.includes('showTitled("err", unlockErrorMessage(r?.code, el<HTMLInputElement>("email").value.trim()));'));
});

test("entry 8: another address names both, the one dialed and the one the verified card names", () => {
  const m = chooseServerMessage({ code: "origin_mismatch", mismatch: { dialed: "https://a.example", named: "https://b.example" } }, "https://vault.andvaripass.com");
  assert.deepEqual(m, {
    title: "This address doesn't match the server's identity card",
    body: "The server at https://a.example showed an identity card made for a different address, https://b.example. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.",
  });
  // The baked public instance: the entry's own rule gives the store builds' sentence instead.
  assert.deepEqual(chooseServerMessage({ code: "origin_mismatch", mismatch: { dialed: "https://vault.andvaripass.com", named: "https://b.example" } }, "https://vault.andvaripass.com"), {
    title: null,
    body: SERVER_MOVED_UPDATE,
  });
  assert.equal(SERVER_MOVED_UPDATE, "This server says it moved. Update andvari.");
  // No addresses in the answer: no slot is filled from anywhere else.
  assert.deepEqual(chooseServerMessage({ code: "origin_mismatch" }, "https://vault.andvaripass.com"), { title: null, body: chooseServerCopy("origin_mismatch") });
  assert.deepEqual(chooseServerMessage({ code: "unavailable" }, "x"), { title: null, body: chooseServerCopy("unavailable") });
  // Both surfaces take the worker's answer whole; neither builds the addresses itself.
  assert.ok(read("./popup.ts").includes('showTitled("err", chooseServerMessage(r, PUBLIC_INSTANCE.origin));'));
  assert.ok(read("./options.ts").includes("const m = chooseServerMessage(r, PUBLIC_INSTANCE.origin);"));
  assert.ok(read("./background.ts").includes('return { ok: false, code: "origin_mismatch", mismatch: { dialed: origin, named: first.cardOrigin } };'));
});

test("entry 10: the kind change gate has its title, Continue and Not now", () => {
  assert.equal(GATE_TITLE_KIND_CHANGE, "This server says it changed");
  const popup = read("./popup.ts");
  assert.ok(popup.includes("title.textContent = GATE_TITLE_KIND_CHANGE;"));
  assert.ok(popup.includes("follow.textContent = T.CONTINUE;") && popup.includes("later.textContent = T.NOT_NOW;"));
  assert.ok(popup.includes('await ask({ type: "deferServerChange", hash });'));
  const html = read("../popup.html");
  assert.ok(html.includes('<strong id="card-notice-title" class="card-notice-title" hidden></strong>'));
  assert.ok(html.includes('<button id="card-notice-later" class="link dim" type="button" hidden>Not now</button>'));
});

test("a message with a title and paragraphs reaches the page as text only, in the live-region order", () => {
  const f = fakeHost();
  setLiveMsgBlocks(f.host, "msg err", "alert", "A <b>title</b>", "one <img src=x onerror=alert(1)>\n\ntwo");
  assert.deepEqual(f.writes, ["role=alert", "children=3"], "role first, then the content in one write");
  assert.equal(f.host.hidden, false);
  assert.deepEqual(
    f.made.map((e) => [e.tag, e.className, e.textContent]),
    [
      ["strong", "msg-title", "A <b>title</b>"],
      ["p", "msg-para", "one <img src=x onerror=alert(1)>"],
      ["p", "msg-para", "two"],
    ],
    "the markup is the text itself",
  );
  assert.deepEqual(messageBlocks(null, "only"), [{ tag: "p", className: "msg-para", text: "only" }]);
  assert.deepEqual(messageBlocks("", "x\n"), [{ tag: "p", className: "msg-para", text: "x" }]);
  const g = fakeHost();
  renderBlocks(g.host, []);
  assert.deepEqual(g.writes, ["children=0"]);
  // The module writes no markup anywhere.
  const src = read("./livemsg.ts");
  for (const bad of ["innerHTML", "outerHTML", "insertAdjacentHTML", "createContextualFragment", "DOMParser"]) assert.ok(!src.includes(bad), bad);
});

test("filling is one pass: a value that reads {0} is copied, an unknown slot is left", () => {
  assert.equal(fillApproved("{0} {1}", "a {1}", "b"), "a {1} b");
  assert.equal(fillApproved("{0} {1}", "x"), "x {1}");
});
