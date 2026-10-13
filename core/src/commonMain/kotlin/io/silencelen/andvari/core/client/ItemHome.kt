package io.silencelen.andvari.core.client

/**
 * Where item plaintext came from, and therefore the ONLY vault it may be sealed under (security review 2026-10, root
 * cause A §5.1 INV-SEAL; branch A1b). Every item seal goes through [Account.sealItem], which takes one of these. No wire
 * field, lookup by itemId or label may pick the sealing key: a caller names the provenance it actually has.
 */
sealed class SealProvenance(val vaultId: String) {
    /** (a) The vault bound in the AD of the envelope the plaintext was decrypted from. */
    class Envelope(vaultId: String) : SealProvenance(vaultId)

    /** (b) The vault an editor session was bound to when it OPENED (user-authored content). */
    class Editor(vaultId: String) : SealProvenance(vaultId)

    /** (c) A destination the user explicitly chose and saw: move, copy, import, or the new-item vault picker. */
    class Chosen(vaultId: String) : SealProvenance(vaultId)
}

/** INV-EDIT: the editor was bound to another vault than the item's home now. Never re-targeted. */
class ItemChangedVaultsException : Exception(HouseholdCopy.ITEM_CHANGED_VAULTS)

/**
 * The item-home rules (security review 2026-10, root cause A §5.1: INV-HOME, INV-CONFLICT, INV-EDIT and the INV-SEAL
 * home cross-check; branch A1b). Pure, so `spec/test-vectors/itemhome.json` grades exactly what [SyncEngine] calls; the
 * web twin is `web/src/vault/itemhome.ts` and the extension's is `extension/src/itemhome.ts`.
 *
 * `home(itemId)` is the vaultId of the FIRST envelope this device applied for that itemId. It is device-local and never
 * a server value after that first row: the server can choose the first home on a fresh device (a stated residual), but
 * it can never move an item this device already holds into another vault. No legitimate flow re-homes an itemId: move
 * and copy mint fresh ids and then delete the source.
 */
object ItemHome {
    /** What to do with one served row (live or tombstone). */
    enum class Admit(val code: String) {
        /** No home yet: this row's vault becomes the home, and the row applies. */
        NEW_HOME("new_home"),

        /** The row is under the item's home: it applies. */
        HOME("home"),

        /** The row names another vault than the home: not applied; quarantined; the pull raises one anomaly. */
        QUARANTINE("quarantine"),
    }

    fun admit(home: String?, rowVaultId: String): Admit = when {
        home == null -> Admit.NEW_HOME
        home == rowVaultId -> Admit.HOME
        else -> Admit.QUARANTINE
    }

    /** INV-CONFLICT for a flagged row. */
    enum class Conflict(val code: String) { MATERIALIZE("materialize"), ABORT("abort") }

    /**
     * Materialize a conflict-flagged row only when nothing disagrees about its vault: the in-memory twin (if any) and
     * the home (if any) must both be the flagged row's vault. Both mutations are then built from `decrypt(flagged)`
     * under `flagged.vaultId`. Anything else aborts with no push (INV-HOME should already have quarantined the row;
     * this is the second lock).
     */
    fun conflict(twinVaultId: String?, flaggedVaultId: String, home: String?): Conflict =
        if ((twinVaultId != null && twinVaultId != flaggedVaultId) || (home != null && home != flaggedVaultId)) Conflict.ABORT
        else Conflict.MATERIALIZE

    /** The push-side copy from a server-returned displaced value. */
    enum class ServerItem(val code: String) { COPY("copy"), ABORT("abort") }

    /**
     * The displaced value must be the item THIS client wrote, in the vault it wrote it to: the vault it decrypts under
     * (its AD vault, which is also the seal vault of the copy) must equal the pushed mutation's vault and the home.
     */
    fun serverItem(pushedVaultId: String, losingVaultId: String, home: String?): ServerItem =
        if (losingVaultId != pushedVaultId || (home != null && home != losingVaultId)) ServerItem.ABORT else ServerItem.COPY

    /** INV-EDIT for an editor save. */
    enum class Edit(val code: String) { OK("ok"), CHANGED_VAULTS("changed_vaults"), UNBOUND("unbound") }

    /** An edit names the vault its editor opened on; a different home now refuses it ("reopen it"), never re-targets. */
    fun edit(home: String?, editorVaultId: String?): Edit = when {
        editorVaultId == null -> Edit.UNBOUND
        home != null && home != editorVaultId -> Edit.CHANGED_VAULTS
        else -> Edit.OK
    }

    /** The INV-SEAL home cross-check every item seal for a push runs. */
    enum class Seal(val code: String) { OK("ok"), NEW_HOME("new_home"), REFUSE("refuse") }

    /** A seal of itemId under [vaultId] is allowed only at its home; an item with no home yet takes this vault as home. */
    fun seal(home: String?, vaultId: String): Seal = when {
        home == null -> Seal.NEW_HOME
        home == vaultId -> Seal.OK
        else -> Seal.REFUSE
    }

    /** One pull's wrong-vault tally: however many rows were refused, the pull raises ONE anomaly. */
    class Tally {
        var refused = 0
            private set
        var firstVaultId: String? = null
            private set

        fun note(vaultId: String) {
            if (refused++ == 0) firstVaultId = vaultId
        }

        fun anomalies(): Int = if (refused > 0) 1 else 0
    }
}
