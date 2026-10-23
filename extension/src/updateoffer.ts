// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (updateoffer.test.ts).
import { DEFAULT_SERVER_URL } from "./serverurl.ts";
import { isNewerVersion } from "./version.ts";

/**
 * The self-update offer's "Download & reload" link (security review 2026-10, branch A15, step 0).
 *
 * The offer is VERIFIED when it is fetched (updateverify.ts: the detached Ed25519 signature over the exact manifest
 * bytes, the anti-rollback seq, the staleness window), but before A15 it was trusted on READ: the stored record was
 * re-checked only for its version, and the popup linked whatever URL it held. A record that did not come from the
 * verified fetch path (pre-A15, any content script could write it through chrome.storage.local) therefore put an
 * arbitrary link into the extension's own UI, where "unzip over the folder and reload" is the documented update.
 *
 * Now the link has exactly one shape, `${DEFAULT_SERVER_URL}/downloads/<basename>`, and exists only while the current
 * server IS the default: the pinned key signs the reference instance's /downloads only (updateverify.ts header), and
 * a self-host origin runs no update channel at all. Releases emit the relative `/downloads/<basename>` form
 * (scripts/release-spec.sh), so nothing real is refused. Both the worker (fetch and read) and the popup (before
 * setting the href) apply it.
 */

/** A file name and nothing else: no slash, no dot-dot, no query or fragment, no percent-escape, bounded. */
const BASENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DOWNLOADS = "/downloads/";

/** The absolute link for a manifest/stored URL, or null when it is not `${DEFAULT_SERVER_URL}/downloads/<basename>`
 *  (relative or absolute) or the current server is not the default. */
export function offerDownloadUrl(u: unknown, currentServer: string): string | null {
  if (currentServer !== DEFAULT_SERVER_URL || typeof u !== "string") return null;
  let rest: string;
  if (u.startsWith(DOWNLOADS)) rest = u.slice(DOWNLOADS.length);
  else if (u.startsWith(DEFAULT_SERVER_URL + DOWNLOADS)) rest = u.slice(DEFAULT_SERVER_URL.length + DOWNLOADS.length);
  else return null;
  if (!BASENAME_RE.test(rest) || rest.includes("..")) return null;
  return DEFAULT_SERVER_URL + DOWNLOADS + rest;
}

export interface UpdateOffer {
  latest: string;
  chromeUrl: string | null;
  firefoxUrl: string | null;
}

/** A STORED offer, re-checked on read: the current server is the default, `latest` is strictly newer than what is
 *  installed, and each link passes [offerDownloadUrl] again (a link that does not is dropped, the offer stays). */
export function readUpdateOffer(raw: unknown, currentVersion: string, currentServer: string): UpdateOffer | null {
  if (currentServer !== DEFAULT_SERVER_URL) return null;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.latest !== "string" || !isNewerVersion(o.latest, currentVersion)) return null;
  return { latest: o.latest, chromeUrl: offerDownloadUrl(o.chromeUrl, currentServer), firefoxUrl: offerDownloadUrl(o.firefoxUrl, currentServer) };
}
