import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../bytes";
import { ed25519PkToCurve25519, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { encodeStatement } from "./codec";
import { signFrame } from "./frame";
import {
  type CardHead, type CardPinRecord, checkBakedRoot, checkKitRoot, checkOfferRoot, checkTypedRoot, followPin, headOf, operatorIdentityKey,
  pinRecordOf, verifyCard, verifyCardChain,
} from "./instancecard";
import { expectSections, gradeEvery, vector } from "./vectors";

/**
 * The instance card of design 2026-11-15 §4, graded off the SAME `instancecard.json` core's
 * `InstanceCardVectorTest` consumes: the chains with the pin record of every card, one rejection per
 * chain rule and the check order (VR-10), a served chain against a pin (fork and withheld, §4.4), the
 * first-pin roots with the dialed origin (VR-12), and the operator's own device (VR-11).
 */
const v = vector("instancecard.json");

interface VectorCard { frameB64: string; hash: string; record: CardPinRecord; why: string }
const chains: Record<string, VectorCard[]> = Object.fromEntries(v.chains.map((c: { name: string; cards: VectorCard[] }) => [c.name, c.cards]));
const frames = (list: string[]): Uint8Array[] => list.map(fromB64);
const verdictOf = (r: { ok: boolean; verdict?: string }): string => (r.ok ? "ok" : r.verdict!);

/** Every base-chain card's head, by hash: the vector's `pin` names only `{card0Hash, seq, hash}`, and following needs the key that card names. */
const headsByHash: Record<string, CardHead> = Object.fromEntries(
  Object.values(chains).flat().map((c) => [c.hash, {
    instanceId: c.record.instanceId, card0Hash: c.record.card0Hash, seq: c.record.seq, hash: c.record.hash, operatorSignKey: c.record.operatorSignKey,
  }]),
);

beforeAll(async () => {
  await initSodium();
});

describe("instancecard.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, ["_about", "instanceId", "keys", "chains", "reject", "pinned", "roots", "operatorDevice"]);
  });

  it("chains: every card verifies in order and gives its pin record", () => {
    gradeEvery("instancecard.chains", v.chains, (chain: any) => {
      let head: CardHead | null = null;
      gradeEvery(`instancecard.chains.${chain.name}`, chain.cards as VectorCard[], (c, i) => {
        const card = verifyCard(head, fromB64(c.frameB64));
        expect(verdictOf(card), `${chain.name}[${i}] ${c.why}`).toBe("ok");
        if (!card.ok) return;
        expect(card.value.hash, `${chain.name}[${i}]`).toBe(c.hash);
        expect(pinRecordOf(card.value), `${chain.name}[${i}]`).toEqual(c.record);
        head = headOf(card.value);
      });
    });
  });

  it("reject: every rejection gets its exact verdict, at that card", () => {
    gradeEvery("instancecard.reject", v.reject, (r: any) => {
      const prefix = verifyCardChain(chains[r.chain]!.slice(0, r.after).map((c) => fromB64(c.frameB64)));
      expect(prefix.verdict, r.name).toBeNull();
      const prior = r.after === 0 ? null : headOf(prefix.cards[prefix.cards.length - 1]!);
      expect(verdictOf(verifyCard(prior, fromB64(r.frameB64))), `${r.name}: ${r.why}`).toBe(r.expect.verdict);
    });
  });

  it("pinned: a served chain against a pin is ok, fork or withheld", () => {
    gradeEvery("instancecard.pinned", v.pinned, (r: any) => {
      const served = frames(r.frames);
      // The rows serve chains that verify from card 0; the verdict is the pin's alone.
      expect(verifyCardChain(served).verdict, r.name).toBeNull();
      const head = headsByHash[r.pin.hash]!;
      expect([head.card0Hash, head.seq], r.name).toEqual([r.pin.card0Hash, r.pin.seq]);
      const follow = followPin(head, served);
      expect(follow.pin ?? "ok", `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (follow.pin === null) {
        expect(follow.verdict, r.name).toBeNull();
        const newest = follow.newer.length === 0 ? { seq: head.seq, hash: head.hash } : { seq: follow.newer.at(-1)!.fields.seq, hash: follow.newer.at(-1)!.hash };
        expect(newest, r.name).toEqual(r.expect.newest);
      } else {
        expect(follow.newer, r.name).toEqual([]);
      }
    });
  });

  it("roots: the first pin, in the pinning order, with the dialed origin", () => {
    const kinds = new Set<string>();
    gradeEvery("instancecard.roots", v.roots, (r: any) => {
      kinds.add(r.root.root);
      expect(typeof r.dialedOrigin, r.name).toBe("string");
      const chain = verifyCardChain(frames(r.frames));
      expect(chain.verdict, r.name).toBeNull();
      let verdict: string | null;
      switch (r.root.root) {
        case "baked": verdict = checkBakedRoot(chain.cards, r.dialedOrigin, r.root.card0Hash, r.root.instanceId); break;
        case "kit": verdict = checkKitRoot(chain.cards, r.dialedOrigin, r.root.card0Hash); break;
        case "link_offer": verdict = checkOfferRoot(chain.cards, r.dialedOrigin, r.root.cardHash, r.root.instanceId); break;
        case "typed": verdict = checkTypedRoot(chain.cards, r.dialedOrigin); break;
        default: throw new Error(`unknown root ${r.root.root}`);
      }
      expect(verdict ?? "ok", `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (verdict === null) expect(pinRecordOf(chain.cards.at(-1)!), r.name).toEqual(r.expect.pinned);
    });
    expect([...kinds].sort()).toEqual(["baked", "kit", "link_offer", "typed"]);
  });

  it("operatorDevice: operator_key_mismatch on the operator's own device only, after bad_signature", () => {
    gradeEvery("instancecard.operatorDevice", v.operatorDevice, (r: any) => {
      // §4.1: the device is handed `self` = {userId, signPubB64}, the Ed25519 key it derives from its own identity seed.
      const self = r.self as { userId: string; signPubB64: string } | null;
      if (self !== null && typeof self.signPubB64 !== "string") {
        throw new Error(`${r.name}: self is not {userId, signPubB64}: this instancecard.json predates §4.1's comparison on the Ed25519 key`);
      }
      const own = self === null ? null : fromB64(self.signPubB64);
      const operatorKeys = self === null ? undefined : (userId: string) => (userId === self.userId ? own : null);
      const result = verifyCardChain(frames(r.frames), null, operatorKeys === undefined ? {} : { operatorKeys });
      expect(result.verdict ?? "ok", `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (r.expect.failedAt !== undefined) expect(result.failedAt, r.name).toBe(r.expect.failedAt);
      if (r.expect.verdict === "ok") expect(result.failedAt, r.name).toBeNull();
    });
  });

  it("a handover that names the NEGATION of the incoming operator's key is refused on that operator's device", () => {
    const outgoing = signKeypairFromSeed(fromB64(v.keys.operator.seedB64));
    const incoming = signKeypairFromSeed(fromB64(v.keys.operator2.seedB64));
    // -A: the same y, with the sign bit of x flipped. Another key, with the SAME X25519 image as A.
    const negated = incoming.publicKey.slice();
    negated[31] = negated[31]! ^ 0x80;
    expect(toB64(negated)).not.toBe(toB64(incoming.publicKey));
    expect(toB64(ed25519PkToCurve25519(negated))).toBe(v.keys.operator2.identityPubB64);
    expect(toB64(operatorIdentityKey(toB64(negated))!)).toBe(v.keys.operator2.identityPubB64);

    const card0 = chains.base![0]!;
    const c0 = verifyCard(null, fromB64(card0.frameB64));
    expect(c0.ok).toBe(true);
    if (!c0.ok) return;
    const sign = (signer: typeof outgoing, seq: number, prev: string, operatorSignKey: Uint8Array): Uint8Array =>
      signFrame(signer, "instance-card", encodeStatement("instance-card", {
        instanceId: card0.record.instanceId, seq: String(seq), prev, origin: card0.record.origin, name: card0.record.name, kind: card0.record.kind,
        operator: v.keys.operator2.userId, operatorSignKey: toB64(operatorSignKey), recoveryFp: card0.record.recoveryFp, issuedAt: String(1763164800000 + seq),
      }));
    const ownDevice = (userId: string) => (userId === v.keys.operator2.userId ? incoming.publicKey : null);

    // The outgoing operator really signs the handover, so every other client accepts it...
    const handover = sign(outgoing, 1, c0.value.hash, negated);
    const elsewhere = verifyCard(headOf(c0.value), handover);
    expect(verdictOf(elsewhere)).toBe("ok");
    // ...and only the incoming operator's device can tell that the key named is not its own.
    expect(verdictOf(verifyCard(headOf(c0.value), handover, { operatorKeys: ownDevice }))).toBe("operator_key_mismatch");
    // What the check prevents: under the negated key, the real key can sign no later card.
    if (!elsewhere.ok) return;
    const byTheRealKey = sign(incoming, 2, elsewhere.value.hash, incoming.publicKey);
    expect(verdictOf(verifyCard(headOf(elsewhere.value), byTheRealKey))).toBe("not_authorized");

    // An honest handover passes on that device.
    expect(verdictOf(verifyCard(headOf(c0.value), sign(outgoing, 1, c0.value.hash, incoming.publicKey), { operatorKeys: ownDevice }))).toBe("ok");
    // The check takes the Ed25519 key: the X25519 identity key in its place refuses even the device's own honest card.
    const x25519InItsPlace = (userId: string) => (userId === v.keys.operator.userId ? fromB64(v.keys.operator.identityPubB64) : null);
    expect(verdictOf(verifyCard(null, fromB64(card0.frameB64), { operatorKeys: x25519InItsPlace }))).toBe("operator_key_mismatch");
    const ed25519 = (userId: string) => (userId === v.keys.operator.userId ? fromB64(v.keys.operator.signPubB64) : null);
    expect(verdictOf(verifyCard(null, fromB64(card0.frameB64), { operatorKeys: ed25519 }))).toBe("ok");
  });

  it("a card for the server's own instance id only, when the server passes it", () => {
    const base = chains.base!;
    const card0 = fromB64(base[0]!.frameB64);
    expect(verdictOf(verifyCard(null, card0, { expectedInstanceId: base[0]!.record.instanceId }))).toBe("ok");
    expect(verdictOf(verifyCard(null, card0, { expectedInstanceId: "ffffffff-ffff-4fff-8fff-ffffffffffff" }))).toBe("instance_mismatch");
  });

  // A brand is a type and is erased at run time, so a verified
  // value stays verified only if no caller can change it.
  it("a verified card cannot be changed after the fact", () => {
    const base = chains.base!;
    const served = fromB64(base[0]!.frameB64);
    const card = verifyCard(null, served);
    expect(card.ok).toBe(true);
    if (!card.ok) return;
    const record = pinRecordOf(card.value);
    const open = card.value as any; // what a caller without the types sees
    const other = toB64(signKeypairFromSeed(fromB64(v.keys.operator2.seedB64)).publicKey);
    const changes: Record<string, () => void> = {
      "the operator's key": () => { open.fields.operatorSignKey = other; },
      "the operator": () => { open.fields.operator = v.keys.operator2.userId; },
      "the origin": () => { open.fields.origin = "https://elsewhere.example.org"; },
      "the recovery key": () => { open.fields.recoveryFp = "0".repeat(64); },
      "the fields": () => { open.fields = { ...open.fields, operatorSignKey: other }; },
      "the hash": () => { open.hash = "0".repeat(64); },
      "the chain's root": () => { open.card0Hash = "0".repeat(64); },
      "the frame": () => { open.frame = new Uint8Array(1); },
    };
    for (const [what, change] of Object.entries(changes)) expect(change, what).toThrow(TypeError);
    expect(pinRecordOf(card.value)).toEqual(record);
    expect(headOf(card.value).operatorSignKey).toBe(base[0]!.record.operatorSignKey);

    // The bytes of a typed array cannot be frozen, so the frame is handed out as a copy: writing into
    // what was read, or into the array that was verified, changes nothing the card holds.
    const read = card.value.frame;
    expect(read).toEqual(fromB64(base[0]!.frameB64));
    read.fill(0);
    served.fill(0);
    expect(card.value.frame).toEqual(fromB64(base[0]!.frameB64));
    expect(card.value.frame).not.toBe(card.value.frame);
  });

  it("following stops at the first card after the pin that does not verify", () => {
    const base = chains.base!;
    const served = base.slice(0, 4).map((c) => fromB64(c.frameB64));
    const broken = served[3]!.slice();
    broken[40] = broken[40]! ^ 1; // a signature bit (offsets 37..101)
    const follow = followPin(headsByHash[base[1]!.hash]!, [...served.slice(0, 3), broken]);
    expect(follow.pin).toBeNull();
    expect(follow.newer.map((c) => c.fields.seq)).toEqual([2]);
    expect(follow.verdict).toBe("bad_signature");
  });
});
