import { act, createElement } from "react";
import { onTestFinished } from "vitest";
import type { ApiClient } from "../api/client";
import type { Browser } from "../vault/fakesyncserver.testkit";
import type { UsageWire } from "../vault/usage";
import { draw, type Drawn, openPage, settle } from "./dom.testkit";
import { Vault } from "./Vault";

/**
 * The vault screen drawn in a test over a real store: [who] is a browser of `fakesyncserver.testkit.ts` (a real
 * `VaultStore` with its shared vaults on the real log layer), and the screen is drawn by React into a happy-dom page
 * (see `dom.testkit.ts`). The screen's own server traffic is the store's; the events socket is replaced by [bell], which
 * rings the dirty bell as the server would (the screen then syncs), and the usage ledger answers "nothing stored".
 * What it cannot do: a second socket, and a real timer of the 60-second poll (the test rings the bell instead). The
 * breach check's range requests are recorded ([ranges]) and answered with an empty range.
 */
export interface DrawnVault extends Drawn {
  /** Rings the dirty bell, as the events socket does when the server's log moved; the screen syncs and the result is drawn. */
  bell(): Promise<void>;
  /** Every breach range the screen asked for (the 5-hex prefixes), in order. */
  readonly ranges: string[];
  /** The page's whole text. */
  text(): string;
  /** The page's whole markup (every attribute and every field's value included, as `outerHTML` writes them). */
  html(): string;
}

export async function drawVault(who: Browser): Promise<DrawnVault> {
  const page = openPage();
  // The screen opens on the view its address names (a test before this one may have left another view's fragment).
  page.history.replaceState(null, "", "/");
  let onRev: ((rev: number) => void) | null = null;
  const ranges: string[] = [];
  const client = {
    events: (rev: (rev: number) => void) => {
      onRev = rev;
      return () => {
        onRev = null;
      };
    },
    hibpRange: async (prefix: string) => {
      ranges.push(prefix);
      return "";
    },
  } as unknown as ApiClient;
  const usageWire: UsageWire = { usage: async () => ({ sealedUsage: null }), putUsage: async () => ({}) };
  const drawn = await draw(
    createElement(Vault, {
      account: who.account,
      store: who.store,
      client,
      usageWire,
      email: `${who.person.userId.slice(0, 8)}@example.org`,
      policy: null,
      isAdmin: false,
      mustChangePassword: false,
      offlineRecoveryReminder: false,
      onLock: () => {},
      onRevoked: () => {},
    }),
  );
  await settle();
  // Taken down when the test ends, passed or failed, so that the next test's page holds nothing of this one.
  let mounted = true;
  onTestFinished(async () => {
    if (mounted) await drawn.unmount();
  });
  return {
    ...drawn,
    ranges,
    unmount: async () => {
      mounted = false;
      await drawn.unmount();
    },
    bell: async () => {
      if (onRev === null) throw new Error("the screen holds no events socket");
      const ring = onRev;
      await act(async () => ring(0));
      // The sync the bell starts runs the real store over the fake server's answers: let every await of it settle.
      await settle(40);
    },
    text: () => drawn.page.textContent ?? "",
    html: () => {
      // A field's typed value lives in its property, not in an attribute: write each into the copy that is searched.
      const doc = drawn.page.ownerDocument;
      const values = [...doc.querySelectorAll("input, textarea")].map((f) => (f as HTMLInputElement).value).join("\n");
      return `${doc.body.outerHTML}\n${values}`;
    },
  };
}

/** The element whose own text is [text] exactly (the first of them), or undefined. */
export function byText(page: ParentNode, text: string): HTMLElement | undefined {
  return [...page.querySelectorAll("*")].find((e) => e.textContent === text && [...e.children].every((c) => c.textContent !== text)) as HTMLElement | undefined;
}
