/**
 * F80: the brand (ᛅ) and empty-hoard (ᛝ) marks drawn as inline SVG. The runic
 * codepoints render as tofu wherever no installed font covers the Runic block,
 * and the CSP posture (self-contained, no external assets) bars shipping one —
 * so the glyphs are geometry. Strokes inherit currentColor: the existing .sigil
 * color tokens keep working in both themes.
 */

/**
 * ᛅ (long-branch ár), the wordmark rune: a stave crossed by one falling stroke.
 *
 * H138 (audit 2026-09-13): THIS geometry is the brand mark, fleet-wide. 0.26.3 shipped two —
 * the tile icons (favicon, desktop .ico/.png, extension icon16-128) drew a 14-unit inset stave
 * at the same stroke 1.8, so the rune on the tab and the taskbar was ~29 % bolder and shorter
 * than the one in the popup header beside it. The owner picked the wordmark; the tiles are now
 * rendered from assets/brand/andvari-mark.svg (this stave, 3-unit inset, on the rx=5 dark tile)
 * by scripts/gen-brand-icons.sh, and app-android ic_launcher_foreground.xml re-draws it as a
 * vector drawable. Change the numbers below and you have changed the product's icon everywhere:
 * update the shared SVG + the Android drawable in the same commit and re-run the generator —
 * brand-assets.test.ts fails when the three disagree.
 */
export function BrandSigil({ size = 46 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" aria-hidden="true">
      <path d="M12 3v18" />
      <path d="M5.5 8.5l13 6" />
    </svg>
  );
}

/** ᛝ (Ingwaz), the empty-state mark, reduced to its enclosing diamond. */
export function EmptySigil({ size = 40 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 4.5 19 12l-7 7.5L5 12Z" />
    </svg>
  );
}
