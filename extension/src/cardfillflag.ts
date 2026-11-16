/**
 * In-page card fill, per build (owner decision 2026-11-14: the first App Store version ships without it; it keeps being
 * reviewed and comes in a later update). build.mjs defines __ANDVARI_CARDFILL__ for every target: the Safari build has
 * it off unless built with CARDFILL=1 (the UI tests and the card-preview build); the Chrome and Firefox builds keep it
 * on unless built with CARDFILL=0.
 *
 * With it off, the worker's card release entry points answer [CARD_FILL_OFF] and are not even bundled (background.ts
 * gates them on the define itself, so esbuild drops them; build.mjs and cardfillflag.test.ts check); nor is the content
 * script's in-page card fill: its chip, its choice of a field, its report of a frame's card forms and its fill (content.ts
 * gates them the same way, and build.mjs and cardfillflag.test.ts check that too; card capture stays). The popup lists
 * cards with the line errors.ts cardFillOffLine gives for the target (Safari: copy the number and code in the app; Chrome
 * and Firefox: the popup's own copy buttons).
 *
 * Anything that loads the source unbundled (node --test, tsc) sees it on, so the card-fill rules stay tested.
 *
 * LEAF module: no chrome import.
 */
declare const __ANDVARI_CARDFILL__: boolean | undefined;

export const CARD_FILL: boolean = typeof __ANDVARI_CARDFILL__ === "boolean" ? __ANDVARI_CARDFILL__ : true;

/** The fixed answer of every card release entry point in a build without card fill. */
export const CARD_FILL_OFF = "card fill is not in this build";
