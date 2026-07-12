import { cloneElement, type CSSProperties, type ReactElement, type ReactNode, useId } from "react";

/**
 * P1 label association (a11yweb-01). Wraps a SINGLE labelable control, injecting a
 * useId-stable id and pointing the visible `<label htmlFor>` at it — so a screen reader
 * speaks the label on focus instead of "edit box, blank". `label` CSS is already
 * `display:block` (styles.css), so this reproduces the existing `.field` block verbatim
 * plus the association.
 *
 * `label` is ReactNode so a nested badge / copy-flash can ride inside it; `hint` renders
 * advisory text (strength bar, "passwords don't match", muted notes) AFTER the control,
 * inside the same `.field` so spacing is preserved.
 *
 * BL-2: apply ONLY to blocks whose single child is itself a labelable element
 * (`input` / `select` / `textarea`). For `.secret-row` wrappers, `PasswordField` (which
 * never forwards `id` to its inner input), and multi-control blocks, put an `aria-label`
 * on the actual inner `<input>` instead — `cloneElement` here would land the id on a
 * wrapper `<div>` and associate the label with nothing.
 */
export function Field({
  label,
  children,
  hint,
  style,
}: {
  label: ReactNode;
  children: ReactElement;
  hint?: ReactNode;
  /** Preserves the inline `.field` styling some rows rely on (e.g. `flex: 1`). */
  style?: CSSProperties;
}) {
  const id = useId();
  return (
    <div className="field" style={style}>
      <label htmlFor={id}>{label}</label>
      {cloneElement(children, { id })}
      {hint}
    </div>
  );
}
