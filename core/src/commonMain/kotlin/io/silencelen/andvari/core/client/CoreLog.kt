package io.silencelen.andvari.core.client

/**
 * The one observability seam :core owns (ux-error--4). Core is deliberately IO-free and
 * clock-free — it must never choose a sink, a format or a severity ladder — so a diagnostic
 * it wants a host to be able to SEE is handed over here and the host decides where it lands
 * (Android `Log`, a desktop log file, a UI banner, an admin escalation, or nowhere).
 *
 * Deliberately one method and no dependency: this is a seam, not a logging framework. There
 * is no level, no timestamp (core has no clock) and no formatting — [event] is a stable
 * machine code a client may key off (route it, count it, escalate it), [detail] is the
 * already-composed human sentence. New codes are additive; an existing one is a contract.
 *
 * The default is [Silent]: a host that wires nothing behaves exactly as it does today. The
 * natives wiring their existing surfaces to it is client work, not core's.
 */
fun interface CoreLog {
    fun warn(event: String, detail: String)

    companion object {
        /** Discards everything — the default for every core component that takes a [CoreLog]. */
        val Silent: CoreLog = CoreLog { _, _ -> }

        /**
         * A delivered vault metaBlob whose `metaV` regressed below the held one (spec 02 §4
         * warn-and-keep-newer, [SyncEngine.keepNewerMeta]). Security-relevant: the honest
         * server never replays, so this is a rolled-back or tampered row. [detail] names the
         * vault and both counters.
         */
        const val EVENT_VAULT_META_REPLAY = "vault_meta_replay"

        /**
         * The sweep of the records kept by the id of accounts the device no longer knows removed nothing this time: the
         * store could not list its keys, or a record it must read to decide could not be read. [detail] names which.
         */
        const val EVENT_ACCOUNT_SWEEP_HELD_BACK = "account_sweep_held_back"

        /** The same sweep stopped at a removal the store refused; the next start goes on. [detail] names the record. */
        const val EVENT_ACCOUNT_SWEEP_STOPPED = "account_sweep_stopped"

        /**
         * The record of an account's deletions begun and not finished held entries that could not be read, or could not be
         * read at all: it was written again from the entries that read, and nothing was removed for those dropped. [detail]
         * says how many were dropped.
         */
        const val EVENT_DELETION_RECORD_REWRITTEN = "deletion_record_rewritten"
    }
}
