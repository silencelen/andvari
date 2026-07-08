import { useEffect, useState } from "react";
import { qrModules } from "../vendor/qrcode-generator";
import { isPrivateOrigin } from "./origin";
import { QrSvg } from "./QrSvg";

/**
 * "Get andvari on your other devices" hub (v6-QW1). Honest surfaces only — every row
 * points at something that actually exists:
 *  - web: the very origin the user is reading this on;
 *  - Android: the devstore (tailnet-only — labelled as such), with a scannable QR;
 *  - Windows: the /downloads/manifest.json the server already serves (B4 made it
 *    honest) — a link once the owner publishes an MSI, a plain "not yet" until then.
 * There is deliberately no browser-extension row: it does not exist yet.
 *
 * All of this advertises pointers, so it hides on the public break-glass origin (same
 * posture as export suppression — shared isPrivateOrigin). No wire change: the manifest
 * is same-origin, the QR renders text the page already holds.
 */

// The household app store. Tailnet-only (no MagicDNS `devstore` host); the bare
// devserv name is the canonical URL. Matches scripts/ship.sh's DEVSERV target.
const DEVSTORE_URL = "https://devserv.taila2dff2.ts.net";

// Computed once — DEVSTORE_URL is constant, and the vendored encoder is pure.
const DEVSTORE_MODULES = qrModules(DEVSTORE_URL, "M");

/** Server /downloads/manifest.json shape (mirror of desktop Platform.kt DownloadsManifest). */
interface PlatformBuild {
  version?: string;
  url?: string;
}
export interface DownloadsManifest {
  windows?: PlatformBuild | null;
  linux?: PlatformBuild | null;
}

export type WindowsRow =
  | { kind: "loading" }
  | { kind: "unpublished" }
  | { kind: "available"; version: string; url: string };

/**
 * Pure decision for the Windows row — the whole point of the manifest fetch, kept
 * node-testable. `null` = still fetching, `"error"` = 404/network (the steady state
 * today; NOT an error to the user), otherwise the parsed manifest. Only a manifest
 * carrying BOTH a version and a url is a real download.
 */
export function windowsRowState(manifest: DownloadsManifest | null | "error"): WindowsRow {
  if (manifest === null) return { kind: "loading" };
  const win = manifest === "error" ? null : manifest.windows;
  if (win && typeof win.url === "string" && win.url && typeof win.version === "string" && win.version) {
    return { kind: "available", version: win.version, url: win.url };
  }
  return { kind: "unpublished" };
}

function WindowsRow({ state }: { state: WindowsRow }) {
  if (state.kind === "loading") return <p className="muted">Checking…</p>;
  if (state.kind === "available") {
    return (
      <p className="muted">
        <a href={state.url}>Download the Windows installer (andvari {state.version})</a>
      </p>
    );
  }
  return <p className="muted">The Windows installer isn’t published yet — it will appear here when it is.</p>;
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
      .then((m) => live && setManifest(m as DownloadsManifest))
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
              Install from <span className="mono">{DEVSTORE_URL}</span> — the household app store (reachable on
              the home network). Updates arrive there too.
            </p>
            <QrSvg modules={DEVSTORE_MODULES} ariaLabel={`Install QR code for ${DEVSTORE_URL}`} />
          </div>

          <div className="field">
            <label>Windows</label>
            <WindowsRow state={windowsRowState(manifest)} />
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
