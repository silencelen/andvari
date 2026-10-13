package io.silencelen.andvari.core.model

/**
 * The id grammar at the wire boundary (security review 2026-10, plugin scan F1; branch A10).
 *
 * Every id the server supplies — vaultId, userId, itemId, deviceId, the user ids riding a transfer — is checked
 * here, in the API client, BEFORE it can reach account state, a cache row or a device-local trust record. The
 * grammar is the lowercase RFC 4122 form every client mints and the server already enforces on what it ACCEPTS
 * (`requireUuid`, `UUID_RE`); a well-behaved server therefore never serves anything else, and a hostile one — the
 * adversary this design is built against — cannot smuggle a record delimiter, a path segment or a second id
 * inside one. A row carrying a malformed id is REFUSED: dropped from the response, never stored, with the
 * refusal reported so the engine can surface an anomaly. One shared helper per engine: this object, web
 * `api/wireids.ts`, extension `wireids.ts`.
 */
object WireIds {
    val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    fun isUuid(s: String?): Boolean = s != null && UUID_RE.matches(s)

    /** One refused id: [field] names the wire field (dotted for a nested one), [value] is the offending string. */
    data class Refusal(val field: String, val value: String)

    /** A sanitised response plus the refusals it cost. */
    data class Sanitized<T>(val value: T, val refused: List<Refusal>)

    private class Collector {
        val refused = mutableListOf<Refusal>()
        /** True when [value] is a UUID; records a refusal otherwise. */
        fun ok(field: String, value: String?): Boolean {
            if (isUuid(value)) return true
            refused += Refusal(field, value ?: "")
            return false
        }
    }

    fun sanitizeSync(resp: SyncResponse): Sanitized<SyncResponse> {
        val c = Collector()
        val vaults = resp.vaults.filter { v ->
            // Evaluate every field (the report names them all), then keep the row only when all passed.
            val a = c.ok("vaultId", v.vaultId)
            val b = v.pendingTransfer?.let { c.ok("pendingTransfer.toUserId", it.toUserId) } ?: true
            val d = v.lastTransfer?.let { c.ok("lastTransfer.newOwnerUserId", it.newOwnerUserId) } ?: true
            a && b && d
        }
        val grants = resp.grants.filter { g ->
            val a = c.ok("vaultId", g.vaultId)
            val b = c.ok("userId", g.userId)
            a && b
        }
        val items = resp.items.filter { i ->
            val a = c.ok("itemId", i.itemId)
            val b = c.ok("vaultId", i.vaultId)
            a && b
        }
        val removed = resp.removedGrants.filter { c.ok("removedGrants", it) }
        val removedInfo = resp.removedGrantsInfo.filter { c.ok("removedGrantsInfo.vaultId", it.vaultId) }
        val out = if (c.refused.isEmpty()) resp else resp.copy(vaults = vaults, grants = grants, items = items, removedGrants = removed, removedGrantsInfo = removedInfo)
        return Sanitized(out, c.refused)
    }

    fun sanitizeMembers(rows: List<VaultMemberSummary>): Sanitized<List<VaultMemberSummary>> {
        val c = Collector()
        return Sanitized(rows.filter { c.ok("userId", it.userId) }, c.refused)
    }

    fun sanitizeDeletedItems(rows: List<DeletedItem>): Sanitized<List<DeletedItem>> {
        val c = Collector()
        val kept = rows.filter { d ->
            val a = c.ok("itemId", d.itemId)
            val b = c.ok("vaultId", d.vaultId)
            a && b
        }
        return Sanitized(kept, c.refused)
    }

    fun sanitizeDeletedVaults(rows: List<DeletedVaultSummary>): Sanitized<List<DeletedVaultSummary>> {
        val c = Collector()
        return Sanitized(rows.filter { c.ok("vaultId", it.vaultId) }, c.refused)
    }

    /** The served personal wrap names a vault: a malformed id drops the wrap (the account then has no served wrap). */
    fun sanitizeAccountKeys(keys: AccountKeys): Sanitized<AccountKeys> {
        val c = Collector()
        val wrap = keys.personalWrap?.takeIf { c.ok("personalWrap.vaultId", it.vaultId) }
        return Sanitized(if (c.refused.isEmpty()) keys else keys.copy(personalWrap = wrap), c.refused)
    }

    /** A served identity row is refused outright (there is no partial row to keep). */
    fun refusedUser(u: UserLookupResponse): Refusal? = if (isUuid(u.userId)) null else Refusal("userId", u.userId)

    /** A session naming a malformed user or device id is refused outright: both are storage namespace keys. */
    fun refusedSession(s: SessionResponse): Refusal? = when {
        !isUuid(s.userId) -> Refusal("userId", s.userId)
        !isUuid(s.deviceId) -> Refusal("deviceId", s.deviceId)
        else -> null
    }
}
