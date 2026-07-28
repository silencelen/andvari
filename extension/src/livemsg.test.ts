// node --test. Pins the a11y 2a ordering rule the popup's showMsg documents and the other two
// hand-rolled copies had inverted: a live region must be UNHIDDEN, with its role set, before its
// text mutates — otherwise the first message is a static read and screen readers drop it.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { clearLiveMsg, setLiveMsg } from "./livemsg.ts";

/** Records every write in order — the whole contract of this module is the sequence. */
function recorder(): { node: Parameters<typeof setLiveMsg>[0]; writes: string[] } {
  const writes: string[] = [];
  const node = {
    _hidden: true,
    _text: null as string | null,
    _class: "",
    get hidden(): boolean {
      return this._hidden;
    },
    set hidden(v: boolean) {
      this._hidden = v;
      writes.push(`hidden=${v}`);
    },
    get textContent(): string | null {
      return this._text;
    },
    set textContent(v: string | null) {
      this._text = v;
      writes.push(`text=${v ?? ""}`);
    },
    get className(): string {
      return this._class;
    },
    set className(v: string) {
      this._class = v;
      writes.push(`class=${v}`);
    },
    setAttribute(name: string, value: string): void {
      writes.push(`${name}=${value}`);
    },
  };
  return { node, writes };
}

test("setLiveMsg unhides and sets the role BEFORE the text (a11y 2a)", () => {
  const { node, writes } = recorder();
  setLiveMsg(node, "msg err", "alert", "Couldn't switch servers.");
  assert.deepEqual(writes, ["class=msg err", "hidden=false", "role=alert", "text=Couldn't switch servers."]);
  assert.equal(writes.indexOf("hidden=false") < writes.length - 1, true);
  assert.equal(node.textContent, "Couldn't switch servers.");
  assert.equal(node.hidden, false);
});

test("a polite outcome gets role=status, same ordering", () => {
  const { node, writes } = recorder();
  setLiveMsg(node, "msg ok", "status", "Connected.");
  assert.deepEqual(writes, ["class=msg ok", "hidden=false", "role=status", "text=Connected."]);
});

test("clearLiveMsg empties the region while it is still live, then hides it", () => {
  const { node, writes } = recorder();
  setLiveMsg(node, "msg info", "status", "armed");
  writes.length = 0;
  clearLiveMsg(node);
  assert.deepEqual(writes, ["text=", "hidden=true"]);
});

test("a repeated message still re-announces — the text write always lands after the unhide", () => {
  const { node, writes } = recorder();
  setLiveMsg(node, "msg err", "alert", "same");
  clearLiveMsg(node);
  writes.length = 0;
  setLiveMsg(node, "msg err", "alert", "same");
  assert.equal(writes.indexOf("hidden=false") < writes.indexOf("text=same"), true);
});
