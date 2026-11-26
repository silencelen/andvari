package io.silencelen.andvari.core.client.net

import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * How much of a server's answer this device reads, per route: the ONE table [KtorWireClient] reads
 * every response body against, before and after a Trust Gate alike, so an address a person types or a link names can
 * never make the device hold whatever that server sends.
 *
 * A body is read to its route's cap and no further: a `Content-Length` above the cap is refused before any body byte
 * is read, and a body without one is read to the cap plus one byte and refused there. The refusal is
 * `Refused(0, `[BODY_OVER_LIMIT]`)`, and the bytes read are zeroed; nothing of an oversized answer is decoded, kept or
 * acted on. A refusal envelope (any status outside 2xx) is read to [ERROR_BODY] at most, or the route's cap if smaller.
 *
 * The caps come from what the protocol lets a server send on each route (spec 03); each larger one says why. A cap
 * is a ceiling, never a size the device expects. An attachment download keeps the cap its caller passes
 * ([WireClient.fetchBytes] with `maxBytes`, the size its item's record claims); the table's value for it is the ceiling
 * of a download made without one.
 */
object ResponseCaps {
    private const val KIB = 1024L
    private const val MIB = 1024L * 1024

    /** The small default: an answer that is one short JSON object, `ok`, or a short text. */
    const val SMALL: Long = 64 * KIB

    /** A refusal envelope `{error, message, …}`, on any route. */
    const val ERROR_BODY: Long = 64 * KIB

    /** A list of short rows an account holds (its devices, links, vaults, requests). */
    const val LIST: Long = 1 * MIB

    /**
     * `GET /instance`, the card chain (spec 03 §17.1), fetched before any Trust Gate: every card and every recovery
     * rotation the instance ever stored. Each card is a frame of about a kilobyte; 1 MiB holds hundreds.
     */
    const val CARD_CHAIN: Long = 1 * MIB

    /**
     * `GET /vaults/{id}/log` (spec 03 §10.6): at most 500 entries a page, each a frame of at most 1,500 characters
     * (§10.3), so about 0.75 MiB with its framing.
     */
    const val LOG_PAGE: Long = 2 * MIB

    /**
     * `GET /sync` (spec 03 §4) is one answer, not pages: a full snapshot carries every item the account can read. Item
     * ciphertext counts against its owner's quota (100 MiB by default, items and attachments together, §7.1), so 256 MiB
     * holds a full snapshot of an account at the default quota with a large share of other owners' vaults.
     */
    const val SYNC: Long = 256 * MIB

    /**
     * `POST /sync/push`'s answer (spec 03 §5, "Stored items in one answer"): the stored items it echoes total at most
     * the request's own body cap, 8 MiB, beside up to 200 short results and each echoed item's JSON framing.
     */
    const val PUSH_ANSWER: Long = 8 * MIB + 256 * KIB

    /** `GET /items/{id}/versions`: the 10 kept versions (spec 02 §7) of an item at the operator's largest item size, 8 MiB. */
    const val ITEM_VERSIONS: Long = 96 * MIB

    /** `GET /items/deleted`: one short row per tombstoned item in every vault the account reads. */
    const val ITEMS_DELETED: Long = 8 * MIB

    /** `GET` and `PUT /account/state`, `PUT /account/recovery`: a sealed state of at most 1 MiB of base64 (§3) with its frame. */
    const val ACCOUNT_STATE: Long = 2 * MIB

    /** `GET /usage`: a sealed ledger of at most 512 KiB (§3) with its frame. */
    const val USAGE: Long = 1 * MIB

    /** A device link's poll and pickup: a sealed bundle of at most 64 KiB of plaintext (spec 03, device links) with its session. */
    const val DEVICE_BUNDLE: Long = 256 * KIB

    /** `GET /hibp/range/{prefix}`: about a thousand suffix lines, padded. */
    const val HIBP_RANGE: Long = 256 * KIB

    /** `GET /admin/accounts`: one short row per account of the instance, for an instance of about 100,000 accounts. */
    const val ADMIN_ACCOUNTS: Long = 32 * MIB

    /** `GET /admin/audit`: one page of at most 500 rows, each with its short `meta`. */
    const val ADMIN_AUDIT: Long = 2 * MIB

    /** A download made without the caller's own cap: an attachment ([WireRoute.ATTACHMENT_GET]) or a self-hosting file. */
    const val DOWNLOAD: Long = 256 * MIB

    /** An app installer under `/downloads/`. */
    const val INSTALLER: Long = 512 * MIB

    /** The downloads manifest and the self-hosting page. */
    const val MANIFEST: Long = 4 * MIB

    /** The cap of [route]'s success body. */
    fun of(route: WireRoute): Long = when (route) {
        WireRoute.INSTANCE -> CARD_CHAIN
        WireRoute.LOG_FETCH -> LOG_PAGE
        WireRoute.SYNC -> SYNC
        WireRoute.PUSH -> PUSH_ANSWER
        WireRoute.ITEM_VERSIONS -> ITEM_VERSIONS
        WireRoute.ITEMS_DELETED -> ITEMS_DELETED
        WireRoute.ACCOUNT_STATE_GET, WireRoute.ACCOUNT_STATE_PUT, WireRoute.ACCOUNT_RECOVERY_PUT -> ACCOUNT_STATE
        WireRoute.USAGE_GET -> USAGE
        WireRoute.DEVICE_LINK_POLL, WireRoute.DEVICE_LINK_PICKUP -> DEVICE_BUNDLE
        WireRoute.HIBP_RANGE -> HIBP_RANGE
        WireRoute.ADMIN_ACCOUNTS -> ADMIN_ACCOUNTS
        WireRoute.ADMIN_AUDIT -> ADMIN_AUDIT
        WireRoute.ATTACHMENT_GET, WireRoute.SELFHOST_FILE -> DOWNLOAD
        WireRoute.DOWNLOADS_FILE -> INSTALLER
        WireRoute.DOWNLOADS_MANIFEST, WireRoute.SELFHOST -> MANIFEST

        WireRoute.DEVICES, WireRoute.ACCOUNT_RECOVERY_REQUESTS, WireRoute.ACCOUNT_DELETE_PREVIEW,
        WireRoute.VAULT_MEMBERS, WireRoute.VAULTS_DELETED, WireRoute.LINK_ANSWERS,
        WireRoute.ADMIN_ACCOUNT_DEVICES, WireRoute.ADMIN_RECOVERY_REQUESTS, WireRoute.METRICS -> LIST

        WireRoute.CLIENT_POLICY, WireRoute.INSTANCE_CARD_PUT, WireRoute.INSTANCE_ROTATION_PUT, WireRoute.RECOVERY_PUBKEY,
        WireRoute.SIGNUP_START, WireRoute.SIGNUP_VERIFY, WireRoute.REGISTER,
        WireRoute.PRELOGIN, WireRoute.LOGIN, WireRoute.REFRESH, WireRoute.LOGOUT, WireRoute.END_SESSION,
        WireRoute.TOTP_STATUS, WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.TOTP_DISABLE,
        WireRoute.ACCOUNT_KEYS, WireRoute.PASSWORD_CHANGE, WireRoute.ESCROW_SELF, WireRoute.USAGE_PUT,
        WireRoute.DEVICE_REVOKE, WireRoute.REQUIRE_LINK, WireRoute.ACCOUNT_DELETE,
        WireRoute.RECOVERY_SELF_VERIFY, WireRoute.RECOVERY_SELF_COMMIT, WireRoute.RECOVERY_SELF_SETUP, WireRoute.RECOVERY_SELF_CONFIRM,
        WireRoute.ITEM_RESTORE, WireRoute.ITEM_PURGE, WireRoute.ATTACHMENT_UPLOAD,
        WireRoute.EVENTS_TICKET, WireRoute.EVENTS,
        WireRoute.LOG_APPEND, WireRoute.VAULT_META, WireRoute.VAULT_SELF_WRAP,
        WireRoute.LINK_CREATE, WireRoute.LINK_FETCH, WireRoute.LINK_ANSWER, WireRoute.LINK_REVEAL, WireRoute.LINK_ACK, WireRoute.LINK_REVOKE,
        WireRoute.DEVICE_LINK_CREATE, WireRoute.DEVICE_LINK_VIEW, WireRoute.DEVICE_LINK_CLAIM, WireRoute.DEVICE_LINK_NONCE,
        WireRoute.DEVICE_LINK_REVEAL, WireRoute.DEVICE_LINK_APPROVE, WireRoute.DEVICE_LINK_CANCEL,
        WireRoute.RECOVERY_REQUEST_CREATE, WireRoute.RECOVERY_REQUEST_VERIFY, WireRoute.RECOVERY_REQUEST_VETO,
        WireRoute.RECOVERY_REQUEST_POLL, WireRoute.RECOVERY_REQUEST_COMMIT,
        WireRoute.ADMIN_ACCOUNT_DISABLE, WireRoute.ADMIN_ACCOUNT_ENABLE, WireRoute.ADMIN_ACCOUNT_DELETE, WireRoute.ADMIN_DEVICE_REVOKE,
        WireRoute.ADMIN_QUOTA, WireRoute.ADMIN_POLICY_GET, WireRoute.ADMIN_POLICY_PUT, WireRoute.ADMIN_STATUS,
        WireRoute.ADMIN_ESCROW, WireRoute.ADMIN_RECOVERY_FULFIL,
        WireRoute.HEALTHZ, WireRoute.ROBOTS, WireRoute.DOWNLOADS_MANIFEST_SIG -> SMALL
    }

    /** The cap of a refusal envelope on [route]. */
    fun ofRefusal(route: WireRoute): Long = minOf(ERROR_BODY, of(route))

    /** The whole table, one entry per route, for a host or a test to read. */
    val table: Map<WireRoute, Long> by lazy { WireRoute.entries.associateWith { of(it) } }
}
