import { decodeName } from "../crypto/trust/grammar";
import type { OperatorOffer } from "../vault/settingsflow";
import {
  RECOVERY_FAMILY_CONFIRM_BODY,
  RECOVERY_FAMILY_CONFIRM_TITLE,
  RECOVERY_FAMILY_OPTION,
  RECOVERY_FAMILY_OPTION_DETAIL,
  RECOVERY_FAMILY_UNDERSTAND,
  RECOVERY_KEEP_NEW_KEY,
  RECOVERY_ONLY_ME,
  RECOVERY_ONLY_ME_DETAIL,
  RECOVERY_QUESTION,
  RECOVERY_UNSIGNED_BODY,
  RECOVERY_UNSIGNED_TITLE,
} from "./copy";
import { Announcer } from "./Msg";

export interface RecoveryChoiceValue {
  readonly posture: "private" | "operator";
  readonly understood: boolean;
  readonly keepNewKey: boolean;
}

export const ONLY_ME: RecoveryChoiceValue = { posture: "private", understood: false, keepNewKey: false };

/** True when [v] may be sent: "Only me", or the operator with its box ticked and any unsigned change kept. */
export function recoveryChoiceReady(v: RecoveryChoiceValue, offer: OperatorOffer | null): boolean {
  if (v.posture === "private") return true;
  return offer !== null && v.understood && (offer.unsignedChanges.length === 0 || v.keepNewKey);
}

/**
 * The recovery choice at sign-up on a private (family) instance (design §7.7, its exact family copy). "Only me" is
 * selected by default. The instance name and origin are the pinned card's, as the offer carries them, rendered as
 * plain text; never a name the server reports for an account (T2-R-f). An offer whose walk found an unsigned key
 * change shows §4.5's warning and needs "Keep it with the new key" as well.
 */
export function RecoveryChoice({ offer, value, onChange }: { offer: OperatorOffer; value: RecoveryChoiceValue; onChange: (v: RecoveryChoiceValue) => void }) {
  const name = decodeName(offer.name) ?? offer.origin;
  const fill = (s: string) => s.replace("{instance name}", name).replace("{name}", name).replace("{origin}", offer.origin);
  return (
    <fieldset className="recovery-choice">
      <legend>{RECOVERY_QUESTION}</legend>
      <Announcer text={value.posture === "operator" ? fill(RECOVERY_FAMILY_CONFIRM_TITLE) : ""} />
      <label className="check">
        {/* One text box beside the radio: `.check` is a flex row, so a bare name and detail would be two squeezed columns. */}
        <input type="radio" name="recovery" checked={value.posture === "private"} onChange={() => onChange(ONLY_ME)} />{" "}
        <span>
          <strong>{RECOVERY_ONLY_ME}</strong> — {RECOVERY_ONLY_ME_DETAIL}
        </span>
      </label>
      <label className="check">
        <input type="radio" name="recovery" checked={value.posture === "operator"} onChange={() => onChange({ ...ONLY_ME, posture: "operator" })} />{" "}
        <span>
          <strong>{fill(RECOVERY_FAMILY_OPTION)}</strong> — {RECOVERY_FAMILY_OPTION_DETAIL}
        </span>
      </label>
      {value.posture === "operator" && (
        <div className="msg info">
          <p>
            <strong>{fill(RECOVERY_FAMILY_CONFIRM_TITLE)}</strong>
          </p>
          <p>{RECOVERY_FAMILY_CONFIRM_BODY}</p>
          {offer.unsignedChanges.length > 0 && (
            <div className="msg err" role="alert">
              <p>
                <strong>{fill(RECOVERY_UNSIGNED_TITLE)}</strong>
              </p>
              <p>{RECOVERY_UNSIGNED_BODY}</p>
              <label className="check">
                <input type="checkbox" checked={value.keepNewKey} onChange={(e) => onChange({ ...value, keepNewKey: e.target.checked })} /> {RECOVERY_KEEP_NEW_KEY}
              </label>
            </div>
          )}
          <label className="check">
            <input type="checkbox" checked={value.understood} onChange={(e) => onChange({ ...value, understood: e.target.checked })} /> {RECOVERY_FAMILY_UNDERSTAND}
          </label>
        </div>
      )}
    </fieldset>
  );
}
