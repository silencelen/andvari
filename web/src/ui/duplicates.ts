import type { ItemDoc } from "../api/types";
import { pslResolve } from "../vault/psl";
import type { VaultItem } from "../vault/store";
import { parseSavedUri } from "../vault/urimatch";

/**
 * Duplicate-entry detection + the guided-merge plan (owner-requested 2026-08-12; ROADMAP P6).
 *
 * Two ways the vault legitimately grows duplicates, both by DESIGN elsewhere: the extension's
 * locked-at-capture save records a recoverable NEW item rather than risking the 2b clobber
 * (savetarget.ts), and importers mint renamed copies rather than corrupting an uncertain match
 * (csv.ts "imported separately for review"). This module is the other half of those bargains:
 * find the copies and offer the safe consolidation.
 *
 * Pure and exported for pinning (the healthRows idiom — duplicates.test.ts): clustering,
 * survivor choice and the merge plan are all decided HERE; Health.tsx only renders and writes.
 *
 * Clustering: LOGIN items group when they share a SITE key (the registrable domain of any saved
 * web uri — the same eTLD+1 authority autofill matching uses; a host the PSL can't resolve
 * (IP, single-label, public-suffix) keys as the normalized host itself, and androidapp:// uris
 * key as the package) AND the same normalized username (trim + lowercase — display keeps the
 * exact strings). Transitive: an item saved for both example.com and example.co.uk bridges its
 * two site-mates into one cluster. Items with NO resolvable site key never cluster — without a
 * site, equal credentials could still be different accounts.
 *
 * kind: "exact" = every member's password is byte-identical (the mergeable tier — the
 * locked-capture/import twins). "differs" = same site + username but diverging passwords: one
 * of them is stale (a password change captured as new); members are newest-first so the UI can
 * say which. Never auto-merged — only the human knows which password the site accepts.
 *
 * 2026-08-18 (owner decisions): two endings for the clusters the merge can't touch. planKeep is
 * the DIFFERS resolution — the human picks the surviving copy, the losers' passwords land in its
 * passwordHistory before the losers go to the Trash. planDismiss/clusterSignature/dupeAck is the
 * "not duplicates — keep both" acknowledgment for clusters that are correct as they stand
 * (same-host services on different ports; the deliberate cross-vault twins), doc-level so it
 * syncs and self-invalidating on any membership change.
 *
 * VAULTS (audit F03). Clustering deliberately spans vaults — the app MINTS cross-vault twins by
 * design ("Copy to vault…", and copyAllToPersonal's shared-vault delete rescue), so hiding them
 * would hide the duplicates a household is most likely to have. But a merge across a sharing
 * boundary deletes the OTHER members' copy: report the cluster, refuse the merge. Same shape as
 * the diverging-TOTP/notes refusals — visible, explained, done by hand. A view-only (reader)
 * vault refuses too: neither the survivor's save nor a loser's remove would be allowed, and a
 * half-completed merge is the worst outcome of all.
 */

export interface DuplicateMember {
  itemId: string;
  vaultId: string;
  name: string;
  /** exact stored username (clustering normalizes; display must not) */
  username: string;
  updatedAt: number;
  hasTotp: boolean;
  /** the member's first saved WEB uri, verbatim — the "open site" affordance for the differs
   *  resolution flow (owner decision 2026-08-18): the only honest password test is the human
   *  logging in; the client must never probe a site with candidate credentials itself. */
  firstUri?: string;
}

/** The ready-to-write consolidation for an ELIGIBLE exact cluster: save `doc` over the
 *  survivor, then remove the losers (they land in Deleted items — the 30-day Trash — so a
 *  wrong merge is recoverable). `doc` is composed HERE so the tests pin exactly what ships. */
export interface MergePlan {
  survivorId: string;
  loserIds: string[];
  doc: ItemDoc;
}

export interface DuplicateCluster {
  /** display: the site keys the members share (union, sorted) */
  sites: string[];
  /** members newest-first — for "differs", the first is the copy most likely current */
  members: DuplicateMember[];
  kind: "exact" | "differs";
  /** exact clusters: the plan, or (exclusively) the human-readable refusal */
  merge?: MergePlan;
  mergeRefusal?: string;
  /** identity of the cluster AS CONSTITUTED (clusterSignature) — the dismissal token */
  signature: string;
  /** every member carries this signature as its dupeAck: the user said "not duplicates" */
  dismissed: boolean;
}

/** The dismissal token: the cluster's sorted member ids. Any membership change — a new copy
 *  minted, one merged away — changes the signature, so an old acknowledgment stops matching
 *  and the cluster resurfaces. Joined with "|": itemIds are server-assigned identifiers, so
 *  the delimiter has no forgery surface (unlike the username NUL below). */
export const clusterSignature = (memberIds: string[]): string => [...memberIds].sort().join("|");

/** Site keys for one login item (exported for the tests). */
export function siteKeysOf(doc: ItemDoc): Set<string> {
  const out = new Set<string>();
  for (const raw of doc.login?.uris ?? []) {
    const saved = parseSavedUri(raw);
    if (!saved) continue;
    if (saved.kind === "app") {
      out.add(`app:${saved.pkg}`);
      continue;
    }
    const r = pslResolve(saved.host);
    out.add(r.kind === "registrable" ? r.domain : saved.host);
  }
  return out;
}

const normUser = (doc: ItemDoc): string => (doc.login?.username ?? "").trim().toLowerCase();

/** The caller's role in a vault ("owner" / "writer" / "reader" / null) — Account.roleFor, passed
 *  in so this module stays pure and the refusals below are pinnable. REQUIRED: it used to default
 *  to `() => null`, i.e. "no role information, so every vault is writable", which meant any caller
 *  that simply forgot the argument silently lost the F03 reader refusal and got merge plans over
 *  view-only vaults. A missing lookup is a caller bug, so let the type checker say so rather than
 *  failing open at runtime — a personal vault genuinely has no role and passes `() => null`
 *  explicitly. */
export type RoleFor = (vaultId: string) => string | null;

/** Survivor + plan for an EXACT cluster, or the refusal. Fail-closed: the survivor must carry
 *  every distinct piece of member data (the one one-time code, the one notes text, and the
 *  attachments if any single member holds them) — data split across copies, or diverging
 *  values, refuses rather than quietly dropping anything. Losers' uris are unioned onto the
 *  survivor (raw-string dedupe, survivor's order first) and `favorite` survives if ANY copy
 *  had it. Everything else (passwordHistory, unknown ExtrasOverlay fields) stays the
 *  survivor's own — the losers go to the Trash intact, not into oblivion. */
function planMerge(members: { it: VaultItem }[], roleFor: RoleFor): { merge?: MergePlan; mergeRefusal?: string } {
  // audit F03, first: a cluster that spans vaults is REPORT-ONLY. Merging one would delete a
  // copy out of a shared vault — from every other member's devices, on every device, with the
  // household never told — for a "duplicate" whose whole point is that it lives in two places.
  if (new Set(members.map((m) => m.it.vaultId)).size > 1) {
    return { mergeRefusal: "These copies are in different vaults — merge by hand." };
  }
  // audit F03: a reader can be neither survivor (the save is denied) nor loser (the remove is
  // denied and the merge half-completes, some copies already in the Trash). The cluster shares
  // ONE vault by the check above, so this refuses the whole merge rather than a subset — the
  // filter is what guarantees no reader-held item can reach `loserIds`.
  const writable = members.filter(({ it }) => roleFor(it.vaultId) !== "reader");
  if (writable.length < members.length || writable.length < 2) {
    return { mergeRefusal: "These copies are in a vault you can only view — ask the vault's owner to merge them." };
  }
  const docs = members.map((m) => m.it.doc);
  const totps = [...new Set(docs.map((d) => d.login?.totp ?? "").filter((t) => t !== ""))];
  if (totps.length > 1) return { mergeRefusal: "The copies carry different one-time codes — merge by hand." };
  const notes = [...new Set(docs.map((d) => (d.notes ?? "").trim()).filter((n) => n !== ""))];
  if (notes.length > 1) return { mergeRefusal: "The copies carry different notes — merge by hand." };
  const withAttachments = members.filter((m) => (m.it.doc.attachments?.length ?? 0) > 0);
  if (withAttachments.length > 1) return { mergeRefusal: "More than one copy has attachments — merge by hand." };

  // Candidates: newest-first members that carry every distinct datum found above.
  const sorted = [...members].sort((a, b) => b.it.updatedAt - a.it.updatedAt);
  const candidates = sorted.filter(({ it }) => {
    if (totps.length === 1 && (it.doc.login?.totp ?? "") !== totps[0]) return false;
    if (notes.length === 1 && (it.doc.notes ?? "").trim() !== notes[0]) return false;
    if (withAttachments.length === 1 && it.itemId !== withAttachments[0]!.it.itemId) return false;
    return true;
  });
  const survivor = candidates[0];
  if (!survivor) return { mergeRefusal: "The copies each hold data the others lack — merge by hand." };

  const uris = unionUris(survivor.it.doc, sorted.filter((m) => m.it.itemId !== survivor.it.itemId).map((m) => m.it));
  const favorite = docs.some((d) => d.favorite === true);
  const doc: ItemDoc = { ...survivor.it.doc, login: { ...survivor.it.doc.login, uris } };
  if (favorite) doc.favorite = true;
  return {
    merge: {
      survivorId: survivor.it.itemId,
      loserIds: sorted.filter(({ it }) => it.itemId !== survivor.it.itemId).map(({ it }) => it.itemId),
      doc,
    },
  };
}

/** Losers' uris onto the survivor: raw-string dedupe, the survivor's own order first, then the
 *  others' in the order given (newest-first at both call sites) — planMerge's original rule,
 *  shared with planKeep so the two consolidations can never drift. */
function unionUris(survivorDoc: ItemDoc, others: VaultItem[]): string[] {
  const uris = [...(survivorDoc.login?.uris ?? [])];
  const seen = new Set(uris);
  for (const it of others) {
    for (const u of it.doc.login?.uris ?? []) {
      if (!seen.has(u)) {
        seen.add(u);
        uris.push(u);
      }
    }
  }
  return uris;
}

/** "Keep this one" for a DIFFERS cluster (owner decision 2026-08-18): the human tested which
 *  password the site currently accepts and picked the survivor; retire the rest. Same
 *  fail-closed shape as planMerge — cross-vault and view-only clusters refuse (removing a copy
 *  from a shared vault takes it from everyone), and data only a loser holds (a diverging
 *  one-time code, diverging notes, any attachments) refuses rather than quietly riding into
 *  the Trash's 30-day window. The losers' PASSWORDS are the deliberate exception — they are
 *  what this flow exists to not lose: every distinct one is appended to the survivor's
 *  passwordHistory at the caller's `retiredAt` clock (passed in — this module stays pure), so
 *  even a wrong pick outlives the Trash purge. Docs are looked up FRESH from `items` by id —
 *  a rendered cluster snapshot must never write stale docs. */
export function planKeep(
  items: VaultItem[],
  memberIds: string[],
  keepId: string,
  roleFor: RoleFor,
  retiredAt: number,
): { keep?: MergePlan; keepRefusal?: string } {
  const members = memberIds.map((id) => items.find((it) => it.itemId === id)).filter((it): it is VaultItem => it !== undefined);
  const survivor = members.find((it) => it.itemId === keepId);
  if (members.length !== memberIds.length || members.length < 2 || !survivor) {
    return { keepRefusal: "A copy changed under you — the list refreshes on its own; try again." };
  }
  if (new Set(members.map((m) => m.vaultId)).size > 1) {
    return { keepRefusal: "These copies are in different vaults — merge by hand." };
  }
  if (members.some((m) => roleFor(m.vaultId) === "reader")) {
    return { keepRefusal: "These copies are in a vault you can only view — ask the vault's owner to merge them." };
  }
  const losers = members.filter((m) => m.itemId !== keepId).sort((a, b) => b.updatedAt - a.updatedAt);
  const sTotp = survivor.doc.login?.totp ?? "";
  if (losers.some((m) => (m.doc.login?.totp ?? "") !== "" && (m.doc.login?.totp ?? "") !== sTotp)) {
    return { keepRefusal: "The copies carry different one-time codes — merge by hand." };
  }
  const sNotes = (survivor.doc.notes ?? "").trim();
  if (
    losers.some((m) => {
      const n = (m.doc.notes ?? "").trim();
      return n !== "" && n !== sNotes;
    })
  ) {
    return { keepRefusal: "The copies carry different notes — merge by hand." };
  }
  if (losers.some((m) => (m.doc.attachments?.length ?? 0) > 0)) {
    return { keepRefusal: "A copy being removed has attachments — merge by hand." };
  }
  const have = new Set([survivor.doc.login?.password ?? "", ...(survivor.doc.login?.passwordHistory ?? []).map((h) => h.password)]);
  const retired: { password: string; retiredAt: number }[] = [];
  for (const m of losers) {
    const pw = m.doc.login?.password ?? "";
    if (pw && !have.has(pw)) {
      have.add(pw);
      retired.push({ password: pw, retiredAt });
    }
  }
  const doc: ItemDoc = {
    ...survivor.doc,
    login: {
      ...survivor.doc.login,
      uris: unionUris(survivor.doc, losers),
      passwordHistory: [...(survivor.doc.login?.passwordHistory ?? []), ...retired],
    },
  };
  if (members.some((m) => m.doc.favorite === true)) doc.favorite = true;
  return { keep: { survivorId: keepId, loserIds: losers.map((m) => m.itemId), doc } };
}

/** "Not duplicates — keep both" (owner decision 2026-08-18): stamp every member with the
 *  cluster's signature. A write per member — so a view-only vault refuses — but a CROSS-vault
 *  cluster is fine: unlike a merge, nothing is removed from anywhere, which makes this the
 *  quiet ending for the deliberate cross-vault twins planMerge refuses to touch. An empty
 *  `signature` clears the acknowledgment (un-dismiss) by dropping the key, never writing it
 *  blank. Fresh-doc lookup by id, as in planKeep. */
export function planDismiss(
  items: VaultItem[],
  memberIds: string[],
  signature: string,
  roleFor: RoleFor,
): { writes?: { itemId: string; doc: ItemDoc }[]; dismissRefusal?: string } {
  const members = memberIds.map((id) => items.find((it) => it.itemId === id)).filter((it): it is VaultItem => it !== undefined);
  if (members.length !== memberIds.length) return { dismissRefusal: "A copy changed under you — the list refreshes on its own; try again." };
  if (members.some((m) => roleFor(m.vaultId) === "reader")) {
    return { dismissRefusal: "These copies are in a vault you can only view — ask the vault's owner." };
  }
  return {
    writes: members.map((m) => {
      const doc: ItemDoc = { ...m.doc };
      if (signature) doc.dupeAck = signature;
      else delete doc.dupeAck;
      return { itemId: m.itemId, doc };
    }),
  };
}

export function duplicateClusters(items: VaultItem[], roleFor: RoleFor): DuplicateCluster[] {
  const logins = items
    .filter((it) => it.doc.type === "login")
    .map((it) => ({ it, sites: siteKeysOf(it.doc), user: normUser(it.doc) }))
    .filter((m) => m.sites.size > 0);

  // Union-find over shared (site, username) keys — transitive by design (see header).
  const parent = new Map<number, number>();
  const find = (i: number): number => {
    let r = i;
    while (parent.get(r) !== r) r = parent.get(r)!;
    parent.set(i, r);
    return r;
  };
  const union = (a: number, b: number): void => {
    parent.set(find(a), find(b));
  };
  logins.forEach((_, i) => parent.set(i, i));
  const byKey = new Map<string, number>();
  logins.forEach((m, i) => {
    for (const site of m.sites) {
      // A NUL separator so a username containing the delimiter cannot forge a different
      // item's key. Written as the ESCAPE, never a literal 0x00: a raw NUL makes git treat
      // this whole file as binary, and a security-relevant module nobody can diff or blame
      // is a worse problem than the one the separator solves.
      const key = `${site}\u0000${m.user}`;
      const first = byKey.get(key);
      if (first === undefined) byKey.set(key, i);
      else union(i, first);
    }
  });

  const groups = new Map<number, { it: VaultItem; sites: Set<string> }[]>();
  logins.forEach((m, i) => {
    const r = find(i);
    groups.set(r, [...(groups.get(r) ?? []), m]);
  });

  const clusters: DuplicateCluster[] = [];
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const sorted = [...members].sort((a, b) => b.it.updatedAt - a.it.updatedAt);
    const passwords = new Set(sorted.map(({ it }) => it.doc.login?.password ?? ""));
    const kind: DuplicateCluster["kind"] = passwords.size === 1 ? "exact" : "differs";
    const signature = clusterSignature(members.map((m) => m.it.itemId));
    const cluster: DuplicateCluster = {
      sites: [...new Set(members.flatMap((m) => [...m.sites]))].sort(),
      members: sorted.map(({ it }) => ({
        itemId: it.itemId,
        vaultId: it.vaultId,
        name: it.doc.name || "(untitled)",
        username: it.doc.login?.username ?? "",
        updatedAt: it.updatedAt,
        hasTotp: Boolean(it.doc.login?.totp),
        firstUri: (it.doc.login?.uris ?? []).find((u) => parseSavedUri(u)?.kind === "web"),
      })),
      kind,
      signature,
      // Dismissed only while EVERY member acknowledges exactly this constitution of the
      // cluster — one new/changed member id breaks the match and the cluster resurfaces.
      dismissed: members.every((m) => m.it.doc.dupeAck === signature),
    };
    if (kind === "exact") Object.assign(cluster, planMerge(members, roleFor));
    clusters.push(cluster);
  }
  // Exact (mergeable) clusters first, then by site for a stable render.
  return clusters.sort((a, b) => (a.kind === b.kind ? (a.sites[0] ?? "").localeCompare(b.sites[0] ?? "") : a.kind === "exact" ? -1 : 1));
}
