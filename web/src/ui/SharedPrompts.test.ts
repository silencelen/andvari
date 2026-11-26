import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { SharedLogSession } from "../vault/sharedlogs";
import { ONE_TAP_TITLE, SHARE_CONNECT_FIRST, SHARE_CONNECT_FIRST_UNNAMED } from "./copy";
import { SharedPrompts } from "./SharedPrompts";

/** The shared-vault prompts above the vault list (design §3.6, §6.9, §8.5), rendered statically from a fake session. */

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

function fake(opts: { oneTapDue?: boolean; listed?: string[]; prompts?: string[]; asks?: { owner: string; vault: string }[]; connectFirst?: boolean }): SharedLogSession {
  const entry = (label: string) => ({ record: { userId: A, identityPub: "k", label: "", method: "link", verifiedAt: 1, compared: true, madeOn: A, extra: new Map() }, current: null, labelText: label });
  return {
    contacts: {
      oneTapListDue: () => opts.oneTapDue ?? false,
      list: () => (opts.listed ?? []).map(entry),
      prompts: () => (opts.prompts ?? []).map((l) => ({ record: entry(l).record, labelText: l })),
    },
    pendingAsks: () => (opts.asks ?? []).map((a) => ({ kind: "ask", vaultId: V, owner: A, ownerLabel: a.owner, vaultName: a.vault, addSeq: 1 })),
    undecided: () => (opts.connectFirst ? [V] : []),
    outcome: () => (opts.connectFirst ? { kind: "connect_first", vaultId: V, serverName: null } : null),
  } as unknown as SharedLogSession;
}

const render = (shared: SharedLogSession | null) => renderToStaticMarkup(createElement(SharedPrompts, { shared, onChanged: () => {} }));

describe("SharedPrompts", () => {
  it("renders nothing without a shared-vault layer, and only its empty live region with nothing to ask", () => {
    expect(render(null)).toBe("");
    const idle = render(fake({}));
    expect(idle).toContain('role="status"');
    expect(idle).not.toContain("msg");
  });

  it("the one-tap list shows each contact's label as plain text, all ticked (§8.5), with its Later", () => {
    const html = render(fake({ oneTapDue: true, listed: ["Alice <b>x</b>"] }));
    expect(html).toContain(ONE_TAP_TITLE.replace(/'/g, "&#x27;"));
    expect(html).toContain("Alice &lt;b&gt;x&lt;/b&gt;");
    expect(html).not.toContain("<b>");
    expect(html).toContain('checked=""');
    expect(html).toContain(">Later</button>");
  });

  it("an ask names the current contact and the vault, as plain text", () => {
    const html = render(fake({ asks: [{ owner: "Alice", vault: "<i>Family</i>" }] }));
    expect(html).toContain("Alice wants to share “");
    expect(html).toContain("&lt;i&gt;Family&lt;/i&gt;");
    expect(html).toContain("Accept");
    expect(html).toContain("Decline");
  });

  it("a share from someone not current here says connect first, but not while the one-tap list is still due", () => {
    // The fake's server reports no name for the sender: the unnamed form of §3.6's line.
    const lead = SHARE_CONNECT_FIRST_UNNAMED;
    expect(SHARE_CONNECT_FIRST).toBe("{0} wants to share a vault with you. Connect with them first.");
    expect(render(fake({ connectFirst: true }))).toContain(lead);
    expect(render(fake({ connectFirst: true, oneTapDue: true, listed: ["Alice"] }))).not.toContain(lead);
  });

  it("a contact made on another device waits for one tap", () => {
    expect(render(fake({ prompts: ["Bob"] }))).toContain("Bob was added as a contact on another of your devices");
  });
});
