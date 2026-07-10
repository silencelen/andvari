/**
 * F80: the brand (ᛅ) and empty-hoard (ᛝ) marks drawn as inline SVG. The runic
 * codepoints render as tofu wherever no installed font covers the Runic block,
 * and the CSP posture (self-contained, no external assets) bars shipping one —
 * so the glyphs are geometry. Strokes inherit currentColor: the existing .sigil
 * color tokens keep working in both themes.
 */

/** ᛅ (long-branch ár), the wordmark rune: a stave crossed by one falling stroke. */
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
