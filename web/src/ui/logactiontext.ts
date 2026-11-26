import { ChangeNotStoredError, type LogActionError } from "../vault/store";
import {
  MOVE_WAITING_REFUSED,
  LOG_APPEND_UNCONFIRMED,
  LOG_APPEND_UNREAD,
  LOG_CLOCK_AHEAD,
  LOG_FROZEN,
  LOG_FROZEN_NOT_SENT,
  LOG_HEAD_MOVED,
  LOG_LEAVE_FROZEN_REFUSED,
  LOG_LEAVE_FROZEN_TAKEN,
  LOG_LEAVE_FROZEN_UNKNOWN,
  LOG_NOT_COMPARED,
  LOG_NOT_CURRENT_CONTACT,
  LOG_NOT_MADE,
  LOG_NOT_SENT,
  LOG_NOT_STORED,
  LOG_NOT_TAKEN,
  LOG_READ_ONLY,
  LOG_STORED_UNREAD,
  LOG_UNKNOWN,
  LOG_UNKNOWN_ADD,
  LOG_UNKNOWN_ADD_UNREAD,
  LOG_UNKNOWN_CREATE,
  LOG_UNKNOWN_UNREAD,
  RESEND_DELETE_ASK_GIVEN_UP,
} from "./copy";

/**
 * What the person reads when the signed vault log did not take a sharing action (design §3.7), or has not answered it.
 * The outcome said is the outcome known: "stored" only from the server's own complete answer, "nothing was sent" only
 * when nothing left the browser, "isn't made" only from the server's own refusal of this very frame, and otherwise
 * "can't tell", with what to do (after an addition: look at the member list, the person may hold the vault's key).
 */
export function logActionText(e: LogActionError | ChangeNotStoredError): string {
  if (e instanceof ChangeNotStoredError) {
    switch (e.known) {
      case "stored":
        return LOG_STORED_UNREAD;
      case "not_stored":
        return LOG_NOT_STORED;
      case "unknown":
        // The vault was read from the server again before this is said; where that read could not be made, the line
        // says that what the screen shows of it may be old.
        if (e.action === "create") return LOG_UNKNOWN_CREATE;
        if (e.action === "add") return e.listRead ? LOG_UNKNOWN_ADD : LOG_UNKNOWN_ADD_UNREAD;
        return e.listRead ? LOG_UNKNOWN : LOG_UNKNOWN_UNREAD;
    }
  }
  const o = e.outcome;
  switch (o.kind) {
    case "not_sent":
      return LOG_NOT_SENT;
    case "read_only":
      // A leave of a vault frozen before it: what the server's answer said, the one thing this browser can know of it.
      if (o.leave === "stored") return LOG_LEAVE_FROZEN_TAKEN;
      if (o.leave === "refused") return LOG_LEAVE_FROZEN_REFUSED;
      if (o.leave === "unknown") return LOG_LEAVE_FROZEN_UNKNOWN;
      // A freeze is said by what happened: after the change was sent and answered, nothing of whether it was made.
      if (o.frozen === "sent") return LOG_FROZEN;
      if (o.frozen === "unsent") return LOG_FROZEN_NOT_SENT;
      return LOG_READ_ONLY;
    case "head_moved":
    // A deletion refused because the vault's items changed after its read: only a move's own dealing with a half-made
    // vault names a read point, and it reads again itself; a screen that ever met it says what is so.
    case "items_moved":
      return LOG_HEAD_MOVED;
    case "not_made":
      return LOG_NOT_MADE;
    case "clock_ahead":
      return LOG_CLOCK_AHEAD;
    case "refused":
      return LOG_NOT_TAKEN.replace("{0}", o.code);
    case "not_allowed":
      if (o.reason === "not_a_current_contact") return LOG_NOT_CURRENT_CONTACT;
      if (o.reason === "not_compared") return LOG_NOT_COMPARED;
      if (o.reason === "move_delete_waiting") return MOVE_WAITING_REFUSED;
      if (o.reason === "append_pending") return LOG_APPEND_UNCONFIRMED;
      if (o.reason === "append_unread") return LOG_APPEND_UNREAD;
      if (o.reason === "delete_given_up") return RESEND_DELETE_ASK_GIVEN_UP;
      return LOG_NOT_TAKEN.replace("{0}", o.reason);
  }
}
