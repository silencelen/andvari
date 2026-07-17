import { useEffect, useState } from "react";

/**
 * "Get andvari on your other devices" hub (v6-QW1). Honest surfaces only — every row
 * points at something that actually exists:
 *  - web: the very origin the user is reading this on;
 *  - Windows/Linux: the /downloads/manifest.json the server already serves (B4 made it
 *    honest) — a link once a build is published, a plain "not yet" until then.
 *  - Browser extension: same manifest (`browserExtension` entry) — preferred surfaces are
 *    the Chrome Web Store listing (`chromeStoreUrl`) and a Mozilla-signed `.xpi`
 *    (`firefoxUrl`); plain zips remain the self-host load-unpacked fallback.
 *
 * Endpoint-agnostic pivot (design 2026-07-15 §5.4.4): the origin gate is GONE — the card
 * renders (and fetches the same-origin manifest) everywhere, so a self-host instance's
 * own /downloads is advertised exactly like the reference instance's. The tailnet
 * devstore pointer + its QR are deleted with origin.ts (no baked hostnames in shipped
 * clients, §5.5). No wire change: the manifest is same-origin.
 */

/** Server /downloads/manifest.json shape (mirror of desktop Platform.kt DownloadsManifest). */
interface PlatformBuild {
  version?: string;
  url?: string;
}
export interface ExtensionBuild {
  version?: string;
  /** Store listing for Chrome-family browsers (auto-updating install) — preferred over chromeUrl. */
  chromeStoreUrl?: string;
  chromeUrl?: string;
  /** A `.xpi` here is a Mozilla-signed click-to-install build; a `.zip` is the load-unpacked fallback. */
  firefoxUrl?: string;
}
export interface DownloadsManifest {
  windows?: PlatformBuild | null;
  linux?: PlatformBuild | null;
  browserExtension?: ExtensionBuild | null;
}

export type PlatformRow =
  | { kind: "loading" }
  | { kind: "unpublished" }
  | { kind: "available"; version: string; url: string };
export type WindowsRow = PlatformRow;

export type ExtensionRow =
  | { kind: "loading" }
  | { kind: "unpublished" }
  | { kind: "available"; version: string; chromeStoreUrl?: string; chromeUrl?: string; firefoxUrl?: string };

/**
 * Coerce whatever the manifest fetch parsed into a usable value. `r.json()` can
 * legitimately produce `null` or a non-object (a file literally containing `null`
 * would otherwise be indistinguishable from the "still fetching" state and wedge
 * the row on "Checking…" forever) — anything that isn't a plain object is treated
 * exactly like a 404: unpublished, never an error.
 */
export function coerceManifest(parsed: unknown): DownloadsManifest | "error" {
  return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    ? (parsed as DownloadsManifest)
    : "error";
}

/**
 * Pure decision for a desktop-platform row — the whole point of the manifest fetch,
 * kept node-testable. `null` = still fetching, `"error"` = 404/network (the steady
 * state today; NOT an error to the user), otherwise the parsed manifest. Only a
 * manifest entry carrying BOTH a version and a url is a real download.
 */
export function platformRowState(
  manifest: DownloadsManifest | null | "error",
  key: "windows" | "linux",
): PlatformRow {
  if (manifest === null) return { kind: "loading" };
  const build = manifest === "error" ? null : manifest[key];
  if (build && typeof build.url === "string" && build.url && typeof build.version === "string" && build.version) {
    return { kind: "available", version: build.version, url: build.url };
  }
  return { kind: "unpublished" };
}

/** Kept as the named export the tests pin; now just the windows column of platformRowState. */
export function windowsRowState(manifest: DownloadsManifest | null | "error"): WindowsRow {
  return platformRowState(manifest, "windows");
}

/**
 * Same decision for the browser-extension row. Available needs a version plus AT LEAST
 * one install surface (store listing, Chrome zip, or Firefox build) — a version with no
 * usable link stays "unpublished" so we never render a dead row.
 */
export function extensionRowState(manifest: DownloadsManifest | null | "error"): ExtensionRow {
  if (manifest === null) return { kind: "loading" };
  const ext = manifest === "error" ? null : manifest.browserExtension;
  if (ext && typeof ext.version === "string" && ext.version) {
    const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
    const chromeStoreUrl = str(ext.chromeStoreUrl);
    const chromeUrl = str(ext.chromeUrl);
    const firefoxUrl = str(ext.firefoxUrl);
    if (chromeStoreUrl || chromeUrl || firefoxUrl) {
      return { kind: "available", version: ext.version, chromeStoreUrl, chromeUrl, firefoxUrl };
    }
  }
  return { kind: "unpublished" };
}

function PlatformRowView({ state, noun }: { state: PlatformRow; noun: string }) {
  if (state.kind === "loading") return <p className="muted">Checking…</p>;
  if (state.kind === "available") {
    return (
      <p className="muted">
        <a href={state.url}>
          Download the {noun} (andvari {state.version})
        </a>
      </p>
    );
  }
  return <p className="muted">The {noun} isn’t published yet — it will appear here when it is.</p>;
}

export function ExtensionRowView({ state }: { state: ExtensionRow }) {
  if (state.kind === "loading") return <p className="muted">Checking…</p>;
  if (state.kind === "unpublished") {
    return <p className="muted">The browser extension isn’t published yet — it will appear here when it is.</p>;
  }
  // Preferred installs: the Chrome Web Store listing (auto-updates) and a Mozilla-signed
  // `.xpi` (Firefox click-to-install). A plain zip is the self-host fallback and keeps the
  // load-unpacked instructions — but only for a browser that has no better surface above.
  const xpiUrl = state.firefoxUrl && state.firefoxUrl.endsWith(".xpi") ? state.firefoxUrl : undefined;
  const zipChrome = state.chromeStoreUrl ? undefined : state.chromeUrl;
  const zipFirefox = xpiUrl ? undefined : state.firefoxUrl;
  return (
    <>
      <p className="muted">Autofill in this computer’s browser (andvari {state.version}).</p>
      {(state.chromeStoreUrl || xpiUrl) && (
        <div className="getbtns">
          {state.chromeStoreUrl && (
            <a href={state.chromeStoreUrl} target="_blank" rel="noreferrer">
              Get for Chrome / Edge / Brave
            </a>
          )}
          {xpiUrl && <a href={xpiUrl}>Get for Firefox</a>}
        </div>
      )}
      {(state.chromeStoreUrl || xpiUrl) && (
        <p className="muted">
          {state.chromeStoreUrl &&
            "Chrome-family browsers install from the Chrome Web Store and update automatically."}
          {state.chromeStoreUrl && xpiUrl && " "}
          {/* Honest asymmetry (review 2026-07-17): the self-distributed .xpi has no update_url and
              the in-extension update nag ships un-armed (§M-D3 sentinel key) — so never imply the
              Firefox install updates itself or will announce updates. */}
          {xpiUrl &&
            "Firefox installs the Mozilla-signed add-on directly — approve the prompt it shows. It can’t update itself: when a newer version appears here, install it again from this button."}
        </p>
      )}
      {(zipChrome || zipFirefox) && (
        <>
          <p className="muted">
            {state.chromeStoreUrl || xpiUrl ? "Or download" : "Download"} for{" "}
            {zipChrome && <a href={zipChrome}>Chrome / Edge / Brave</a>}
            {zipChrome && zipFirefox && " or "}
            {zipFirefox && <a href={zipFirefox}>Firefox</a>}, unzip it to a folder you’ll keep, then follow
            the INSTALL.txt inside — about two minutes; the steps differ per browser.
          </p>
          <p className="muted">
            {/* No popup-flag promise: the update nag ships un-armed (§M-D3) — the extension never
                checks this manifest, so the only honest channel is "check back here". */}
            Because it’s loaded unpacked, that copy can’t update itself — check back here for newer versions
            ({state.version} is current). Updating means re-downloading above and reloading it in your
            browser’s extensions page.
          </p>
        </>
      )}
    </>
  );
}

export function DevicesCard({ origin }: { origin?: string }) {
  const here = origin ?? (typeof location !== "undefined" ? location.origin : "");
  const [manifest, setManifest] = useState<DownloadsManifest | null | "error">(null);

  useEffect(() => {
    let live = true;
    fetch("/downloads/manifest.json", { headers: { accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((m) => live && setManifest(coerceManifest(m)))
      .catch(() => live && setManifest("error"));
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="sheet">
      <h2>Get andvari on your other devices</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Every device syncs the same hoard, end-to-end encrypted. Your master password unseals it on each
        one — it is never sent anywhere.
      </p>

      <div className="field">
        <label>Any browser</label>
        <p className="muted">
          Open <span className="mono">{here || "this address"}</span> and sign in with your master password.
        </p>
      </div>

      {/* TODO Wave 3 (design 2026-07-15 §5.4.4, gated on the §8 Gate-1 artifact publish): the fully
          manifest-driven artifact list goes here — render exactly the artifacts /downloads/manifest.json
          lists, with an Android row (URL + install QR) iff an `android` artifact exists. The old
          tailnet-devstore Android pointer was deleted with origin.ts; until the manifest carries an
          android entry there is nothing honest to render for phones. */}

      <div className="field">
        <label>Windows</label>
        <PlatformRowView state={platformRowState(manifest, "windows")} noun="Windows installer" />
      </div>

      <div className="field">
        <label>Linux</label>
        <PlatformRowView state={platformRowState(manifest, "linux")} noun="Linux package (.deb)" />
      </div>

      <div className="field">
        <label>Browser extension</label>
        <ExtensionRowView state={extensionRowState(manifest)} />
      </div>
    </div>
  );
}
