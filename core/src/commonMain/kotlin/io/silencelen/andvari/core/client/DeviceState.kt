package io.silencelen.andvari.core.client

/**
 * Small per-(origin, user) state that must outlive the offline cache (security review 2026-10, root cause A,
 * branch A5b, A5 re-review M-1): the personal wrap this device last authenticated (UVK-sealed) and the
 * personal vault id it pinned. It is NOT the [VaultCache]: that one may be in memory (desktop's default, an
 * org-forbid policy) or wiped (a policy flip, a revocation purge), and with it went the device's memory of
 * the wrap, so after a restart a server that withheld the wrap met a "new" device and the question was asked
 * again. Web keeps the same keys in localStorage; the extension in storage.local.
 *
 * Everything stored here is either a public id or a UVK-sealed blob, so persisting it weakens nothing.
 * Platform stores keep it beside [SelfIdentityPin] and remove it only with the namespace itself.
 */
interface DeviceState {
    fun get(key: String): String?
    fun set(key: String, value: String?)

    /**
     * Every key held, or null when this store cannot list them. Following a move (design §4.4 "A namespace's trust
     * records move with its pin") needs it to carry every per-origin record; a store that answers null cannot follow
     * a move, and the move is refused before either pin is touched.
     */
    fun keys(): Set<String>? = null
}

/** In-memory [DeviceState] (tests, and hosts that persist nothing). */
class MemoryDeviceState : DeviceState {
    private val map = HashMap<String, String>()
    override fun get(key: String): String? = map[key]
    override fun keys(): Set<String> = map.keys.toSet()
    override fun set(key: String, value: String?) {
        if (value == null) map.remove(key) else map[key] = value
    }
}
