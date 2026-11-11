/**
 * Which browser build this bundle is. build.mjs defines __ANDVARI_TARGET__ ("chrome" | "firefox" |
 * "safari") through esbuild; anything that loads the source unbundled (node --test, tsc) sees it
 * undefined and gets "chrome", the historical default.
 *
 * LEAF module: no chrome import, so the node test runner can load it directly.
 */
declare const __ANDVARI_TARGET__: string | undefined;

export type BuildTarget = "chrome" | "firefox" | "safari";

export const BUILD_TARGET: BuildTarget =
  typeof __ANDVARI_TARGET__ === "string" && (__ANDVARI_TARGET__ === "firefox" || __ANDVARI_TARGET__ === "safari")
    ? __ANDVARI_TARGET__
    : "chrome";

/** The Safari build ships inside the iOS app and updates through the App Store, so it must never poll our
 *  /downloads channel or offer a download link. */
export function selfUpdateChannelAllowed(target: BuildTarget = BUILD_TARGET): boolean {
  return target !== "safari";
}

/** On iOS the system's AutoFill fills logins (the andvari app's credential provider), so the Safari build never puts
 *  its own fill menu on a login field. Save capture and the popup are unaffected. */
export function loginFillOverlayAllowed(target: BuildTarget = BUILD_TARGET): boolean {
  return target !== "safari";
}
