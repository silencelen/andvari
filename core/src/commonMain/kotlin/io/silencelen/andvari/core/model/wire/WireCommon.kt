package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/*
 * The wire types of spec 03 (the onboarding and trust overhaul, docs/design/2026-11-15-onboarding-trust.md).
 *
 * One package for every request, response and shared object of spec 03 §0.2's 95 routes. The server
 * and every Kotlin client compile against these classes; the web client mirrors the same JSON in
 * TypeScript. The pre-overhaul DTOs in `io.silencelen.andvari.core.model` stay beside them until the
 * last caller moves, then they are deleted.
 *
 * Conventions (spec 03 §0.1):
 *  - Every binary field is a `String` holding unpadded base64url; the KDoc names its spec type
 *    (`b64_16`, `b64_32`, `frame`, `envelope`, `sealed`, `hex64`, `origin`, …).
 *  - `ms` and `int` values are `Long` (spec 01 §5.1: `0 <= x < 2^53`). Small counts are `Int`.
 *  - Field presence (spec 03 §0.1): a message carries every field it lists, default-valued or not. So:
 *    a listed field has no default, or a non-null default marked `@EncodeDefault` (so `false`, `[]` and
 *    every `kdfParams` key are written); a field the spec marks optional (`field?`) is nullable with a
 *    `null` default and is left out of the JSON when null ([WireJson]); a field whose `null` has a
 *    meaning of its own (`reveal: null`, a quota PUT's limits) is nullable WITHOUT a default, so it is
 *    always encoded. A type whose shapes list different keys ([LinkFetchResponse]) has its own
 *    serializer. `WireFieldPresenceTest` (jvmTest) checks every type of this package and of the route
 *    index against these rules.
 *  - Closed value sets (platform, role, state, kind, …) travel as `String`, with the legal values in
 *    the constant objects below. They are not Kotlin enums on purpose: the server must answer a bad
 *    value with its own `400 bad_<field>` (spec 03 §0.1), which an enum decode failure cannot carry,
 *    and a client MUST ignore what it does not know rather than fail the whole response.
 *  - Nothing here validates a value's grammar except where spec 03 demands a strict decoder
 *    ([RegisterAuth]: exactly one key; [DeviceLinkBundle] and [DeviceLinkOuter]: exactly these keys).
 */

/**
 * The JSON configuration for every type in this package.
 *
 * - [json] ignores unknown keys (spec 03 §0.1: a client MUST ignore response fields it does not know;
 *   a server ignores request fields a route does not take unless the route says otherwise), does not
 *   encode a default value unless the property is marked `@EncodeDefault` (so an optional `null` is
 *   absent on the wire, and a listed field with a non-null default is present), and keeps explicit
 *   nulls (so a no-default nullable field such as [LinkFetchResponse.reveal] is encoded as `null`).
 *   It stays `encodeDefaults = false` on purpose: turned on, every optional `null` would be sent as
 *   `null`, which spec 03 §0.1 allows only where a row gives `null` a meaning.
 * - [strict] refuses unknown keys. It is used only by the decoders spec 03 makes strict.
 */
object WireJson {
    val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
        explicitNulls = true
    }

    val strict: Json = Json {
        ignoreUnknownKeys = false
        encodeDefaults = false
        explicitNulls = true
        isLenient = false
        allowSpecialFloatingPointValues = false
    }
}

/**
 * Every refusal (spec 03 §0.1): `{error, message}` plus, for a few codes, extra top-level fields that
 * the index writes in braces. Each extra field is null unless its code carries it:
 *
 * | code | extra fields |
 * |---|---|
 * | `log_head_moved` | [seq], [hash], [at] (the stored log head, §10.3 step 6) |
 * | `card_head_moved` | [seq], [hash] (the stored card head, §17.2) |
 * | `quota_exceeded` | [quota] (a [QuotaName] value, §14.4) |
 * | `account_delete_blocked` | [blockers] (§13) |
 * | `account_delete_log_stale` | [vaultIds] (§13) |
 * | `not_disabled_long_enough` | [disabledAt] (null when the account is active, §7.1) |
 *
 * Clients key on [error], never on the status or [message] (spec 03 §0.1). [message] is human-only
 * and never rendered as trusted text.
 */
@Serializable
data class WireError(
    val error: String,
    val message: String,
    val seq: Long? = null,
    val hash: String? = null,
    val at: Long? = null,
    val quota: String? = null,
    val blockers: List<AccountDeleteBlocker>? = null,
    val vaultIds: List<String>? = null,
    val disabledAt: Long? = null,
)

/**
 * The `201 {expiresAt, ttlMs}` body of `POST /links` and `POST /device-links` (spec 03 §15.2, §16.2):
 * the expiry the server stored (`ms`, by its clock) and the milliseconds left. The creating device
 * counts down from [ttlMs], never from its own clock against [expiresAt].
 */
@Serializable
data class LinkCreatedResponse(val expiresAt: Long, val ttlMs: Long)

/** The plain-text body `ok` (`text/plain`) of every write route that returns nothing else (spec 03 §0.1). */
object WireOk {
    const val BODY: String = "ok"
    const val CONTENT_TYPE: String = "text/plain"
}

/**
 * A vault log head as fetch, append and the deletion preview serve it (spec 03 §0.1 `head`, §10.6):
 * `seq` an `int`, `hash` a `hex64` (the frame hash, design §2.1), `at` the entry's `ms`.
 *
 * A served head is a hint to fetch and the place to build a new entry; it is never a verdict.
 * What a device believes comes only from the log it verified (spec 03 §10.6, design §3.9).
 */
@Serializable
data class LogHead(val seq: Long, val hash: String, val at: Long)

/**
 * The head that rides a shared vault row in `/sync` (spec 03 §4, §10.6): `{seq, hash}` without `at`.
 * A device whose verified head differs fetches the log; it never adopts this value (design §3.9).
 */
@Serializable
data class SyncLogHead(val seq: Long, val hash: String)

/** The closed `platform` list (spec 03 §0.1, design §2.3). Checked by the server as `400 bad_platform`. */
object WirePlatform {
    const val ANDROID = "android"
    const val IOS = "ios"
    const val WINDOWS = "windows"
    const val MACOS = "macos"
    const val LINUX = "linux"
    const val WEB = "web"
    const val CLI = "cli"
    const val EXTENSION = "extension"
    val ALL: Set<String> = setOf(ANDROID, IOS, WINDOWS, MACOS, LINUX, WEB, CLI, EXTENSION)
}

/** Account roles (spec 03 §2 `SessionResponse.role`, §7). */
object AccountRole {
    const val OPERATOR = "operator"
    const val MEMBER = "member"
}

/** Grant roles on a vault (spec 03 §4 grants, §10.7 members). A log `role` entry carries only writer or reader. */
object VaultRole {
    const val OWNER = "owner"
    const val WRITER = "writer"
    const val READER = "reader"
}

/** Recovery postures (spec 03 §3.1, design §4.5). A served posture is a mirror; clients never act on it. */
object RecoveryPosture {
    const val PRIVATE = "private"
    const val OPERATOR = "operator"
}

/** Instance kinds (spec 03 §7.3, §17). Only the pinned card's `kind` decides anything on a client. */
object InstanceKind {
    const val PUBLIC = "public"
    const val PRIVATE = "private"
}

/** Effective sign-up modes (spec 03 §1.1, §14.4). */
object SignupMode {
    const val OPEN = "open"
    const val LINKS = "links"
    const val CLOSED = "closed"
}

/** Quota names (spec 03 §14.4), carried by `413 quota_exceeded {quota}` and the per-mutation `rejected` reason. */
object QuotaName {
    const val ACCOUNT_BYTES = "accountBytes"
    const val ITEMS = "items"
    const val OWNED_SHARED_VAULTS = "ownedSharedVaults"
    const val OPEN_LINKS = "openLinks"
}
