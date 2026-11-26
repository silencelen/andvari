import { describe, expect, it } from "vitest";
import { AnswerCutOffError, ApiError, RedirectRefusedError, TrafficStoppedError } from "../api/client";
import { UnreadableAnswerError } from "../api/wireclient";
import { ChangeNotStoredError, LogActionError, type MoveResult, MoveStoppedError } from "../vault/store";
import {
  fill,
  LOG_APPEND_UNCONFIRMED,
  LOG_NOT_SENT,
  LOG_NOT_STORED,
  LOG_STORED_UNREAD,
  LOG_UNKNOWN,
  LOG_UNKNOWN_ADD,
  MOVE_DISCARD_FAILED,
  MOVE_DISCARD_WAITING,
  MOVE_DISCARDED,
  MOVE_STOPPED_ADD,
  MOVE_STOPPED_ADD_HELD,
  MOVE_STOPPED_DELETE_HELD,
  MOVE_STOPPED_DELETE_STORED,
  MOVE_STOPPED_REMOVE_HELD,
  MOVE_STOPPED_START,
  RENAME_UNKNOWN,
} from "./copy";
import { moveResultText, moveStoppedText, renameErrorText } from "./Sharing";

const OLD = "Family";
const NEW = "Family 2";
const stopped = (stage: "remove" | "create" | "add" | "delete", cause: unknown) => new MoveStoppedError(stage, 2, 2, NEW, "n", cause);

/**
 * A move's steps, the half-made vault's deletion, and a rename say the outcome known: a step whose signed change is held
 * is never said as "wasn't changed" or "not everyone has been added"; a deletion held for re-sending is never "couldn't
 * be deleted, delete it yourself"; a rename whose answer was lost is "can't tell".
 */
describe("the move's and the rename's lines follow what is known", () => {
  it("a move stopped at its removal: the old vault may have changed, the held removal's own line follows", () => {
    for (const [known, line] of [["unknown", LOG_UNKNOWN], ["not_stored", LOG_NOT_STORED], ["stored", LOG_STORED_UNREAD]] as const) {
      const t = moveStoppedText(stopped("remove", new ChangeNotStoredError("v", "remove", known)), OLD);
      expect(t).toBe(`${fill(MOVE_STOPPED_REMOVE_HELD, OLD)} ${line}`);
      expect(t).not.toContain(fill(MOVE_STOPPED_START, OLD));
    }
    const blocked = moveStoppedText(stopped("remove", new LogActionError({ kind: "not_allowed", reason: "append_pending" })), OLD);
    expect(blocked).toBe(`${fill(MOVE_STOPPED_REMOVE_HELD, OLD)} ${LOG_APPEND_UNCONFIRMED}`);
    // Not sent at all: nothing changed, and the way on is said.
    expect(moveStoppedText(stopped("remove", new LogActionError({ kind: "not_sent", vaultId: "v" })), OLD)).toBe(`${fill(MOVE_STOPPED_START, OLD)} ${LOG_NOT_SENT}`);
  });

  it("a move stopped at an addition whose answer was lost: never 'not everyone has been added'", () => {
    const t = moveStoppedText(stopped("add", new ChangeNotStoredError("n", "add", "unknown")), OLD);
    expect(t).toBe(`${fill(MOVE_STOPPED_ADD_HELD, "", "", NEW, OLD)} ${LOG_UNKNOWN_ADD}`);
    expect(t).not.toContain(fill(MOVE_STOPPED_ADD, "", "", NEW, OLD));
  });

  it("a move's deletion: stored by the server's own answer is said as stored; otherwise signed and waiting", () => {
    const stored = new MoveStoppedError("delete", 2, 2, NEW, "n", new ChangeNotStoredError("v", "delete", "stored"), true);
    expect(moveStoppedText(stored, OLD)).toBe(fill(MOVE_STOPPED_DELETE_STORED, "2", "", NEW, OLD));
    const held = new MoveStoppedError("delete", 2, 2, NEW, "n", new ChangeNotStoredError("v", "delete", "unknown"), true);
    expect(moveStoppedText(held, OLD)).toBe(fill(MOVE_STOPPED_DELETE_HELD, "2", "", NEW, OLD));
  });

  it("the half-made vault: deleted, waiting (held, sent again), or not made", () => {
    const base: MoveResult = { newVaultId: "n", name: NEW, copied: 1, oldDeleted: null, oldKept: "source_stays", notAdded: [], added: 0, uncopyable: 0, changed: 0, discarded: null };
    const with_ = (d: MoveResult["discarded"]) => moveResultText({ ...base, discarded: d }, OLD);
    expect(with_({ vaultId: "h", name: "Half", deleted: false, waiting: true })).toContain(fill(MOVE_DISCARD_WAITING, "Half"));
    expect(with_({ vaultId: "h", name: "Half", deleted: false, waiting: true })).not.toContain(fill(MOVE_DISCARD_FAILED, "Half"));
    expect(with_({ vaultId: "h", name: "Half", deleted: false })).toContain(fill(MOVE_DISCARD_FAILED, "Half"));
    expect(with_({ vaultId: "h", name: "Half", deleted: true })).toContain(fill(MOVE_DISCARDED, "Half"));
  });

  it("a rename: not sent, refused, or can't tell", () => {
    expect(renameErrorText(new TrafficStoppedError("forked", false))).toBe(LOG_NOT_SENT);
    for (const e of [new TrafficStoppedError("forked", true), new TypeError("Failed to fetch"), new ApiError(502, "bad_gateway", "x"), new AnswerCutOffError(200, new TypeError("broke")), new RedirectRefusedError(302), new UnreadableAnswerError("x", false)]) {
      expect(renameErrorText(e), String(e)).toBe(RENAME_UNKNOWN);
    }
    expect(renameErrorText(new ApiError(409, "stale_meta", "x"))).not.toBe(RENAME_UNKNOWN);
  });
});
