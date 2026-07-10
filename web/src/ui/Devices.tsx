import { useEffect, useState } from "react";
import { qrModules } from "../vendor/qrcode-generator";
import { isPrivateOrigin } from "./origin";
import { QrSvg } from "./QrSvg";

/**
 * "Get andvari on your other devices" hub (v6-QW1). Honest surfaces only — every row
 * points at something that actually exists:
 *  - web: the very origin the user is reading this on;
 *  - Android: the devstore (tailnet-only — labelled as such), with a scannable QR behind a
 *    default-off toggle (owner dev-note 2026-07-10);
 *  - Windows/Linux: the /downloads/manifest.json the server already serves (B4 made it
 *    honest) — a link once a build is published, a plain "not yet" until then.
 *  - Browser extension: same manifest (`browserExtension` entry) — Chrome/Firefox zips
 *    published to /downloads, loaded unpacked (household fleet; no store listing).
 *
 * All of this advertises pointers, so it hides on the public break-glass origin (same
 * posture as export suppression — shared isPrivateOrigin). No wire change: the manifest
 * is same-origin, the QR renders text the page already holds.
 */

// The household app store. Tailnet-only (no MagicDNS `devstore` host); the bare
// devserv name is the canonical URL. Matches scripts/ship.sh's DEVSTORE target.
// KNOWN + ACCEPTED (review web-correctness-1): this literal ships in the ONE static
// bundle, so it is view-source-visible even on the public break-glass origin — the
// isPrivateOrigin gate suppresses the DOM/fetch, not the bytes. Accepted because
// tailnet HTTPS hostnames are already public knowledge (ts.net certs land in CT
// logs), and isPrivateOrigin is documented posture, not a security boundary. If
// that posture ever tightens, split this half of the card behind a dynamic import.
const DEVSTORE_URL = "https://devserv.taila2dff2.ts.net";

// Computed once — DEVSTORE_URL is constant, and the vendored encoder is pure.
const DEVSTORE_MODULES = qrModules(DEVSTORE_URL, "M");

/** Server /downloads/manifest.json shape (mirror of desktop Platform.kt DownloadsManifest). */
interface PlatformBuild {
  version?: string;
  url?: string;
}
export interface ExtensionBuild {
  version?: string;
  chromeUrl?: string;
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
  | { kind: "available"; version: string; chromeUrl?: string; firefoxUrl?: string };

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
 * one browser zip (Chrome-family or Firefox) — a version with no usable link stays
 * "unpublished" so we never render a dead row.
 */
export function extensionRowState(manifest: DownloadsManifest | null | "error"): ExtensionRow {
  if (manifest === null) return { kind: "loading" };
  const ext = manifest === "error" ? null : manifest.browserExtension;
  if (ext && typeof ext.version === "string" && ext.version) {
    const chromeUrl = typeof ext.chromeUrl === "string" && ext.chromeUrl ? ext.chromeUrl : undefined;
    const firefoxUrl = typeof ext.firefoxUrl === "string" && ext.firefoxUrl ? ext.firefoxUrl : undefined;
    if (chromeUrl || firefoxUrl) return { kind: "available", version: ext.version, chromeUrl, firefoxUrl };
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

function ExtensionRowView({ state }: { state: ExtensionRow }) {
  if (state.kind === "loading") return <p className="muted">Checking…</p>;
  if (state.kind === "unpublished") {
    return <p className="muted">The browser extension isn’t published yet — it will appear here when it is.</p>;
  }
  return (
    <p className="muted">
      Autofill on this computer’s browser. Download for{" "}
      {state.chromeUrl && <a href={state.chromeUrl}>Chrome / Edge / Brave</a>}
      {state.chromeUrl && state.firefoxUrl && " or "}
      {state.firefoxUrl && <a href={state.firefoxUrl}>Firefox</a>} (andvari {state.version}), unzip it to a
      folder you’ll keep, then follow the INSTALL.txt inside — about two minutes; the steps differ per browser.
    </p>
  );
}

export function DevicesCard({ origin }: { origin?: string }) {
  const here = origin ?? (typeof location !== "undefined" ? location.origin : "");
  const isPrivate = isPrivateOrigin(here);
  const [manifest, setManifest] = useState<DownloadsManifest | null | "error">(null);

  useEffect(() => {
    if (!isPrivate) return; // never advertise device pointers (or fetch) on the public origin
    let live = true;
    fetch("/downloads/manifest.json", { headers: { accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((m) => live && setManifest(coerceManifest(m)))
      .catch(() => live && setManifest("error"));
    return () => {
      live = false;
    };
  }, [isPrivate]);

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

      {isPrivate ? (
        <>
          <div className="field">
            <label>Android</label>
            <p className="muted">
              Install from <span className="mono">{DEVSTORE_URL}</span> — the household app store (the phone
              needs Tailscale). Updates arrive there too.
            </p>
            <AndroidQrToggle />
          </div>

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
        </>
      ) : (
        <div className="field">
          <p className="muted">Device downloads are shown when you’re on the home network.</p>
        </div>
      )}
    </div>
  );
}

/** Owner dev-note 2026-07-10: the Android install QR is behind a toggle, DEFAULT HIDDEN —
 *  it dominated the card visually and is only needed the moment a phone is actually being
 *  pointed at it. The URL text above it stays always-visible (copy/typeable). */
function AndroidQrToggle() {
  const [show, setShow] = useState(false);
  return (
    <>
      <button type="button" className="ghost" onClick={() => setShow((s) => !s)}>
        {show ? "Hide QR code" : "Show QR code"}
      </button>
      {show && <QrSvg modules={DEVSTORE_MODULES} ariaLabel={`Install QR code for ${DEVSTORE_URL}`} />}
    </>
  );
}
