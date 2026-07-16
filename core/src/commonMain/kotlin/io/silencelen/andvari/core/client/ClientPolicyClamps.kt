package io.silencelen.andvari.core.client

/**
 * Client-side ceilings for the server-declared policy timers (design 2026-07-15-multi-tenant-endpoints
 * §2.3, breaker B1-1). `ClientPolicy` is fetched from an UNAUTHENTICATED endpoint on an UNTRUSTED
 * server; `autoLockSeconds` / `clipboardClearSeconds` govern the client device's own exposure windows,
 * so they are CLIENT-FLOOR-ONLY: every client clamps the fetched value into range before applying it.
 * A hostile server may make a client safer, never laxer — a server-supplied 0 / absent / oversized
 * auto-lock (which would mean "never lock") clamps to the ceiling, so a server CANNOT disable
 * auto-lock or pin the clipboard for hours.
 *
 * SINGLE SOURCE for every implementation. Byte-pinned mirrors: `web/src/api/types.ts` +
 * `extension/src/api.ts`, locked by the web vitest pin suite (`web/src/policy-clamps.test.ts`
 * reads THIS file) — bump all three together, deliberately. Any raise ships as a client build
 * constant, never a server value (design §11.5).
 *
 * Wave 1 DEFINES the constants only; the call-site clamping (`useAutoLock.ts`,
 * `AndvariViewModel.kt`, `DesktopState.kt`, extension policy consumers) is wave-2 client work.
 */
object ClientPolicyClamps {
    /** Ceiling for `ClientPolicy.autoLockSeconds` — effective = clamp into [floor, this] (§2.3). */
    const val AUTO_LOCK_MAX_SECONDS = 900

    /** Ceiling for `ClientPolicy.clipboardClearSeconds` — effective = clamp into [1, this] (§2.3). */
    const val CLIPBOARD_CLEAR_MAX_SECONDS = 300
}
