# andvari — accessibility support

**Matrix measured: 2026-07-15. UI framework pinned: Compose Multiplatform (CMP) 1.7.3.**
Re-run the verification protocol (below) whenever `compose-multiplatform` is bumped in
`gradle/libs.versions.toml` — screen-reader bridging is framework capability, so a CMP upgrade
can change these answers.

> Scope: this is the honest, *evidence-first* support posture for assistive technology (screen
> readers) across andvari's clients. It documents what was demonstrated, never what is hoped.
> Source of the protocol: `docs/design/2026-07-13-platform-fit.md` §3.

## The short version

**The Linux desktop app does not currently expose an accessibility tree — screen readers
(Orca) cannot read it. This is a limitation of the UI framework we ship on, not a policy. The
web vault is the accessible path** (it carries our WCAG AA work), **and Windows support requires
the Java Access Bridge steps** documented below.

If you use a screen reader, **use the web vault.** It is the client we test for accessibility.

## Platform support matrix (CMP 1.7.3, measured 2026-07-15)

| Client | AT bridge | Status | Notes |
|---|---|---|---|
| **Web vault** (`web/`) | Browser DOM → platform a11y (NVDA/VoiceOver/Orca) | **Supported — the accessible path** | Carries the project's WCAG AA work. This is where a screen-reader user should go. |
| **Android** (`app-android/`) | Android accessibility framework (TalkBack) | Framework-bridged | Compose for Android bridges semantics to TalkBack; not the subject of this desktop protocol. |
| **Desktop — Windows** (`.msi`) | Java Accessibility API → **Java Access Bridge** → NVDA/JAWS | **Conditional; runtime fix shipped, Phase-2 verify PENDING** | CMP bridges to the Java Accessibility API, which reaches Windows screen readers only through the Java Access Bridge. The bundled runtime now includes `jdk.accessibility` (see below) so the bridge *can* load; the user must still run `jabswitch /enable`. An attended NVDA pass (Phase 2) has **not** yet been run — do not claim "works" until it has. |
| **Desktop — Linux** (`.deb`) | (Java Accessibility API → AT-SPI is **not documented as supported** by JetBrains at CMP 1.7.3) | **EXPECTED FAIL — not exposed** | The app's semantics exist in `Ui.kt` (the a11ydesk cut added contentDescriptions etc.), but CMP 1.7.3 does not bridge them onto the Linux AT-SPI bus. Orca is expected to hear nothing. **Not yet empirically confirmed on a GNOME box — see "Verification status" — but this is the documented posture and the honest default.** |
| **Desktop — macOS** | — | Not a target | No macOS build exists (`targetFormats(Msi, Deb)` only). |

**Ctrl+L / menu bar (2026-07-15):** independent of the screen-reader bridge, the desktop app now
has a native menu bar and a `Ctrl+L` panic-lock — the first *keyboard* path to lock (WCAG 2.1.1
Keyboard), giving every toolbar icon a named, keyboard-traversable menu equivalent. This is a
keyboard-access win on every platform; it does **not** by itself make the Linux tree readable.

## The one in-our-hands remediation (shipped 2026-07-15): `jdk.accessibility`

The jlink runtime image bundled in the `.msi`/`.deb` was minimized and **omitted the
`jdk.accessibility` module**. Without that module the bundled Windows runtime *cannot load the
Java Access Bridge even after the user runs `jabswitch /enable`* — so Windows screen-reader
support was broken at the packaging layer, independent of CMP's capabilities.

Fixed in `app-desktop/build.gradle.kts` — `jdk.accessibility` appended to
`nativeDistributions.modules(...)`. Shipping a runtime that *cannot* load the bridge is strictly
wrong, so this lands even though the Windows (Phase-2) NVDA verification is still pending.

**Empirical support for the fix (observed on the build host, huginn, 2026-07-15):** the JDK 17
image at `/usr/lib/jvm/java-17-openjdk-amd64` ships `jmods/jdk.accessibility.jmod`, so jlink can
bundle it; and that JDK's `conf/accessibility.properties` carries **no uncommented
`assistive_technologies` directive**, i.e. no AT is wired by default — the bridge only engages
when the module is present *and* the platform mechanism (JAB on Windows) is enabled.

### Windows screen-reader setup (Java Access Bridge)

1. Install the andvari `.msi` (which now bundles a runtime containing `jdk.accessibility`).
2. Enable the Java Access Bridge once, per user: open a terminal and run **`jabswitch /enable`**
   (it ships inside the bundled runtime's `bin/`; a system JDK's copy works too), then sign out
   and back in.
3. Start NVDA (or JAWS), then launch andvari.
4. This flow has **not** yet been run end-to-end by us (Phase 2). If it does not speak, the
   accessible fallback is the web vault.

## Verification protocol & status

Three phases, from `docs/design/2026-07-13-platform-fit.md` §3.

### Phase 0 — headless AT-SPI presence probe (no human, no screen reader)

Script: **`app-desktop/a11y-probe.sh`**. It launches the app under `Xvfb` with `at-spi2-core`
running on a private D-Bus session and dumps whether an accessible application node for the
andvari JVM appears in `org.a11y.atspi.Registry` (via `pyatspi` and `busctl --user tree`). It
also re-runs the probe under candidate JVM/CMP enabling flags
(`-Djavax.accessibility.assistive_technologies=…`, `-Dcompose.accessibility.enable=true`) since
JetBrains has historically gated desktop a11y behind system properties.

- **PASS** = an accessible application node for andvari exposes children with roles/names → Orca
  *might* speak → proceed to Phase 1.
- **FAIL** = the app is absent from the registry. This is **conclusive** that Orca hears nothing
  (Orca reads the same bus) — no screen reader or human needed to prove it.

**What could / could not be observed in the build environment (huginn LXC 117, 2026-07-15):**
The probe **could not execute here** and exited *inconclusive* (exit 2) at its dependency gate.
This host is a headless LXC with **no `DISPLAY` and no GUI a11y stack** — `Xvfb`, `xvfb-run`,
`at-spi2-registryd` (at-spi2-core), `python3-pyatspi`, `accerciser`, and `orca` are all absent
(`dbus-run-session` and `busctl` are present, but insufficient alone). The Phase-0 PASS/FAIL
answer therefore **remains unverified** and must be produced on a Linux GNOME box:

```sh
sudo apt-get install -y xvfb at-spi2-core dbus python3-pyatspi
cd app-desktop && ./a11y-probe.sh        # or ANDVARI_BIN=/path/to/andvari ./a11y-probe.sh
```

Record the tree-dump artifact and the PASS/FAIL here when run. The *expectation* to test (not
assert) is **FAIL** — consistent with JetBrains not documenting Linux/AT-SPI support at 1.7.3.

### Phase 1 — attended Orca pass (Linux)

Runs only if Phase 0 PASSes (else moot). GNOME + Orca, three scripted flows (unlock / vault list
/ editor) with per-flow PASS / PARTIAL / SILENT. Note: the desktop client currently has zero
`liveRegion`s (a separate audit item), so error *announcements* may fail even where a tree exists
— record which layer failed. **Status: not run** (blocked on Phase 0).

### Phase 2 — Windows (NVDA)

Runtime already fixed (`jdk.accessibility`, above). Rebuild the `.msi`, `jabswitch /enable`, run
NVDA over the same three flows. **Status: not run** (owner-attended, needs a Windows box).

## Remediation posture (grounded in CMP 1.7.3 — no invented capabilities)

1. **Document + web-vault fallback** — this file. The recommended v1 outcome. **Done.**
2. **`jdk.accessibility` into the runtime image + Windows JAB doc** — **Done** (build line +
   the Windows steps above); Phase-2 re-run still pending.
3. **Track upstream, re-verify on CMP upgrades** — Linux/AT-SPI bridging does not exist at CMP
   1.7.3 and is not buildable by us at sane cost; it would arrive (if ever) via a JetBrains
   release. Re-run Phase 0 whenever `compose-multiplatform` bumps.
4. **REJECTED: hand-rolling an AT-SPI bridge** (JNI to libatspi) — multi-month framework
   engineering for a household app that already has an accessible web client. Named so nobody
   re-derives it.

---

*This matrix is dated and CMP-version-pinned on purpose: a future CMP upgrade re-triggers the
protocol. Never cite it as evidence of support that a protocol run did not demonstrate.*
