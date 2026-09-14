/**
 * H133: the ONE back affordance.
 *
 * The app shipped two glyphs and two casings for the same gesture — "← back to vault" on the
 * item detail, the editor's "← cancel", the import and export panels, against "‹ Back to
 * settings" and "‹ Back to vaults" on the views that came later. Nothing about that is a bug;
 * it is the product reading as several hands, which for a 1.0 is its own kind of defect. The
 * later form wins: the single-chevron guillemet matches the "→" the settings hub uses to go
 * FORWARD (a full arrow reads as a page transition, the chevron as a step back up), and
 * sentence case matches every other control label in the app.
 *
 * `label` is the destination, not the gesture: "Back to vault", "Back to settings". The one
 * exception is the editor's Cancel, which is a two-state control (it arms a discard confirm) and
 * so composes {@link BACK_GLYPH} itself rather than taking this component.
 */
export const BACK_GLYPH = "‹";

export function BackLink({
  label,
  onClick,
  disabled,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button type="button" className="link" onClick={onClick} disabled={disabled}>
      {BACK_GLYPH} {label}
    </button>
  );
}
