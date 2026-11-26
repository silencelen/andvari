import { AnswerCutOffError, ApiError, RedirectRefusedError, TrafficStoppedError } from "../api/client";
import { AnsweredCostRefusedError, UnreadableAnswerError } from "../api/wireclient";
import { KdfPolicyError } from "../crypto/keys";

/**
 * What a write that the person cannot simply make again came to, when its call threw: a registration, or a kit
 * recovery's commit (each replaces or creates what the server keeps of an account, and spends the ticket it carries).
 * "Stored" is said only of what the server itself answered.
 *
 *  - `not_sent`: this browser's own traffic gate refused the request before it left the browser (the server's record
 *    here was forgotten or found forked meanwhile, in this tab or another): nothing was sent, so nothing changed.
 *  - `refused`: the server answered with a refusal (a 4xx): nothing was stored, and the screen may say so.
 *  - `stored`: the server answered with success, in an answer only this server could have given ([answerNamesAccount]:
 *    a JSON object under the JSON type, no `error` in it, naming the account this browser sent, no redirect followed)
 *    that this browser could not take: another shape, or a full answer whose served cost is outside the fence. The
 *    server holds what was sent: the screen never says that nothing was changed.
 *  - `unknown`: whether it was stored cannot be told: no answer, the server's own error (a 5xx), an answer the gate
 *    dropped after it arrived, a redirect, an answer cut off while it came, a success answer that is not the server's
 *    (an empty body, a proxy's or a captive portal's page, a front's own JSON, JSON that names no account or another),
 *    or anything else.
 */
export type SendOutcome = "not_sent" | "refused" | "stored" | "unknown";

/**
 * Why an `unknown` outcome cannot be told, so that the screen says what happened and "the server didn't answer" only
 * when it did not:
 *  - `no_answer`: no answer came (the network failed before any status arrived, or the request was aborted);
 *  - `server_error`: an error answer (a 5xx), from the server or from something in front of it;
 *  - `unreadable`: an answer came, and this browser could not take it as the server's: a success answer that is not the
 *    server's JSON, an answer whose body could not be read to its end, a redirect, an answer its traffic gate dropped,
 *    or any other answer it cannot place.
 */
export type UnknownWhy = "no_answer" | "server_error" | "unreadable";

export function unknownWhy(e: unknown): UnknownWhy {
  // A body that broke off after the status arrived is an answer: checked before the TypeError below, which it may wrap.
  if (e instanceof AnswerCutOffError) return "unreadable";
  if (e instanceof ApiError) return e.status >= 500 ? "server_error" : "unreadable";
  // `fetch` rejects with a TypeError when no answer came, and with an AbortError or TimeoutError when it was stopped.
  const name = typeof e === "object" && e !== null ? (e as { name?: unknown }).name : undefined;
  if (e instanceof TypeError || name === "AbortError" || name === "TimeoutError") return "no_answer";
  return "unreadable";
}

/**
 * Whether a success answer is one only this server could have given for this request: a JSON object (not an array,
 * not null) with no `error` member, whose `userId` is the account this browser sent on that route. A front's own JSON
 * (a proxy's `{"error":…}` at 200, `[]`, `null`, `{}`) names no account, so it never counts.
 */
export function answerNamesAccount(answer: unknown, sentUserId: string): boolean {
  if (answer === null || typeof answer !== "object" || Array.isArray(answer)) return false;
  const o = answer as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(o, "error")) return false;
  return typeof o.userId === "string" && o.userId === sentUserId;
}

/** [sentUserId]: the account this browser sent on the route (the registration's new id, the kit's verified account). */
export function outcomeOfThrow(e: unknown, sentUserId: string): SendOutcome {
  // The gate's error is an ApiError with status 0 but never an answer of the server's: checked first.
  if (e instanceof TrafficStoppedError) return e.sent ? "unknown" : "not_sent";
  if (e instanceof RedirectRefusedError) return "unknown";
  if (e instanceof AnswerCutOffError) return "unknown";
  if (e instanceof AnsweredCostRefusedError) return e.serversJson && answerNamesAccount(e.answer, sentUserId) ? "stored" : "unknown";
  // A cost refusal that carries no answer was not read from one: what the server did cannot be told from it.
  if (e instanceof KdfPolicyError) return "unknown";
  if (e instanceof UnreadableAnswerError) return e.serversJson && answerNamesAccount(e.answer, sentUserId) ? "stored" : "unknown";
  if (e instanceof ApiError) {
    if (e.status >= 400 && e.status < 500) return "refused";
    return "unknown";
  }
  return "unknown";
}
