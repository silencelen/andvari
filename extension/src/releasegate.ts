// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` and from package.mjs.
import { LAST_PRE_A15_VERSION } from "./trustmigrate.ts";
import { isNewerVersion } from "./version.ts";

/**
 * A release fact the code depends on (security review 2026-10, the A16 review): the one-time A15 migration reads
 * storage.local only when the browser reports an update FROM a version no newer than [LAST_PRE_A15_VERSION]
 * (trustmigrate.attestsPreA15Upgrade). A build of this tree — which has the trusted store — released under a version
 * not newer than that would be taken for a pre-A15 build by the next update: an update from it would be attested as the
 * pre-A15 upgrade, and a start whose store had lost its flag would read storage.local again, whatever a content script
 * had written there since (the F2 harm). And an update from the real pre-A15 release to it would not be an update at
 * all.
 *
 * package.mjs (the release packaging step) refuses to package such a version. The check is not in verify.sh on
 * purpose: between releases the tree may carry the last release's version (it does today: 0.28.1), and that is only
 * wrong once the tree is packaged for release.
 *
 * Returns why [version] cannot be released, or null.
 */
export function a15ReleaseProblem(version: string): string | null {
  if (isNewerVersion(version, LAST_PRE_A15_VERSION)) return null;
  return (
    `extension version ${JSON.stringify(version)} is not newer than LAST_PRE_A15_VERSION (${LAST_PRE_A15_VERSION}), the last release ` +
    "without the A15 trusted store: an update from this build would be taken for the pre-A15 upgrade (trustmigrate.ts). " +
    "Bump manifest.json, manifest.firefox.json and package.json — or, if a release without A15 shipped after it, raise LAST_PRE_A15_VERSION."
  );
}
