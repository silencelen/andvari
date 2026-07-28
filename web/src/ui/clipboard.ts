/**
 * ux-error--2 (polish audit 2026-07-27): `navigator.clipboard.writeText` REJECTS in real
 * conditions — "Document is not focused" (click-then-alt-tab), a permissions-policy denial in an
 * embedded context, some Firefox configs — and every copy button here used to fire it unawaited,
 * so the failure surfaced only as an unhandled rejection in the console while the user believed
 * their password was on the clipboard. One guarded write shared by Vault's useCopy and Settings'
 * CopyButton: resolves false instead of ever rejecting; callers render {@link CLIPBOARD_FAILED}
 * (the extension toClipboard's twin behavior — popup.ts shows the same sentence on its catch).
 */
export async function writeClipboard(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
