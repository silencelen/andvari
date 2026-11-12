package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.PersonalChangeDetails
import io.silencelen.andvari.core.client.PersonalChoiceInfo
import io.silencelen.andvari.core.client.PersonalVaultProposal
import io.silencelen.andvari.core.client.ReauthStaleSessionException
import io.silencelen.andvari.core.client.session.VaultSession
import kotlin.coroutines.cancellation.CancellationException

/** What the personal-vault notice is about (the states of [Account.PersonalStatus] other than confirmed). */
enum class PersonalVaultState {
    /** The server sent no record this time; the device kept the one it had. Nothing to decide. */
    WITHHELD,

    /** The server sent a record this account cannot read; the device kept the one it had. Repair by choosing again. */
    UNREADABLE_KEPT,

    /** The server names a personal vault nothing on this device vouches for. No personal vault is in force until the person decides. */
    PROPOSED,

    /** The server names another vault than this device's. The device keeps its own until the person decides. */
    CHANGED,

    /** No record anywhere: the person chooses which vault is personal. */
    UNCHOSEN,

    /** The server sent a record this account cannot read and the device has none: the person chooses, with the master password. */
    UNREADABLE,
}

/** One vault the person may make their personal vault, with what the server reports about it. */
data class PersonalChoiceView(
    val vaultId: String,
    /** "Family · 12 items". */
    val label: String,
    /** Who else holds it and where it came from, as the server reports; empty until that was looked up. */
    val detail: String,
)

/**
 * The confirmation every designation goes through: it names the vault and everyone else on it. Nothing is written
 * until [SessionController.confirmPersonalVault].
 */
data class PersonalProposalView(
    /** "Make Family your personal vault?" or "Keep Family as your personal vault?". */
    val title: String,
    val lines: List<String>,
    /** The lines that are a warning (other people can read this vault). */
    val warning: String?,
    /** It replaces a record the server holds, which takes the master password again. */
    val needsPassword: Boolean,
    val confirmLabel: String,
)

/**
 * The personal-vault notice of an unlocked vault (spec 01 §5, design root cause A §4.3 and §8.5; Android's
 * PersonalVaultBanner, sentence for sentence). Null in [AppState] when the personal vault is confirmed.
 */
data class PersonalVaultView(
    val state: PersonalVaultState,
    val title: String,
    val body: String,
    /** "Keep Family": re-designate the vault this device (or the account) already has; null when there is none to keep. */
    val keepLabel: String?,
    /** What the server reports about the vault it names, once that was looked up. */
    val servedDetail: String?,
    /** "Use Family": offered only after [servedDetail] loaded. */
    val useServedLabel: String?,
    /** The lookup of who else holds the served vault failed; [SessionController.retryPersonalVaultDetails] tries again. */
    val lookupFailed: Boolean,
    /** [PersonalVaultState.UNCHOSEN]: the vaults to choose from. */
    val choices: List<PersonalChoiceView>,
    /** Any own vault may be chosen instead, with the master password (Settings' re-designation on Android). */
    val otherChoices: List<PersonalChoiceView>,
    val proposal: PersonalProposalView?,
    val error: String?,
)

/**
 * The personal-vault question for a native UI: Android's banner and dialogs as state and actions. The rules are the
 * core's ([io.silencelen.andvari.core.client.SyncEngine]): every designation is propose, then confirm; proposing mints
 * nothing; "use the served vault" is refused until its co-holders were loaded; keeping or choosing a vault where the
 * server already holds a record replaces it and takes a fresh master-password reauth.
 */
internal class PersonalVaultFlow(private val publish: (PersonalVaultView?) -> Unit, private val changed: () -> Unit) {
    private var details: PersonalChangeDetails? = null
    private var lookupFailed = false
    private var proposal: PersonalVaultProposal? = null
    private var proposalKeeps = false
    private var error: String? = null

    /** The vault locked or the account went: nothing pending survives. */
    fun reset() {
        details = null
        lookupFailed = false
        proposal = null
        error = null
        publish(null)
    }

    private fun describe(origin: PersonalChoiceInfo.Origin) =
        if (origin == PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER) "received by transfer" else "created by this account"

    /** One line under each option: what the server reports; it informs the person and decides nothing. */
    private fun choiceDetail(info: PersonalChoiceInfo?): String {
        if (info == null) return ""
        val origin = if (info.origin == PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER) "received from someone else by transfer" else "created by this account"
        val holders = info.coHolders.let { h ->
            when {
                h == null -> "couldn't check who else holds it"
                h.isEmpty() -> "nobody else holds it"
                else -> "also held by " + h.joinToString(", ") { "${it.displayName} (${it.role})" }
            }
        }
        return "As reported by the server: $origin · $holders" + if (info.onThisDevice) " · this device's personal vault" else ""
    }

    private fun name(live: VaultSession.Unlocked, vaultId: String): String =
        live.engine.personalChoiceInfo(vaultId).name ?: live.engine.vaultInfos().firstOrNull { it.vaultId == vaultId }?.name ?: "this vault"

    private fun proposalView(p: PersonalVaultProposal): PersonalProposalView {
        val n = p.name ?: "this vault"
        val lines = buildList {
            add("New items, imports and usage history will go to $n by default.")
            if (p.coHolders.isEmpty()) add("The server reports nobody else on this vault.")
            if (p.origin == PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER) add("The server reports that someone else created this vault and transferred it to you.")
        }
        val warning = if (p.coHolders.isEmpty()) null else
            "The server reports that these people can also read everything in it: " + p.coHolders.joinToString(", ") { "${it.displayName} (${it.email})" } + ". Choose it only if that is what you want."
        return if (proposalKeeps) {
            PersonalProposalView("Keep $n as your personal vault?", lines, warning, needsPassword = true, confirmLabel = "Keep it")
        } else {
            PersonalProposalView("Make $n your personal vault?", lines, warning, needsPassword = p.replacing != null || needsReauth, confirmLabel = "Yes, this is my personal vault")
        }
    }

    /** A choice made where the server already holds a record (anything but a first designation) takes the password. */
    private var needsReauth = false

    /** Build the notice for [live] as it stands. Sends nothing. */
    fun render(live: VaultSession.Unlocked) {
        val status = live.account.personalStatus
        if (status == Account.PersonalStatus.CONFIRMED) {
            publish(null)
            return
        }
        val own = live.engine.redesignationChoices().map { v ->
            val info = live.engine.personalChoiceInfo(v.vaultId)
            PersonalChoiceView(v.vaultId, "${v.name} · ${info.itemCount} items", choiceDetail(info))
        }
        val proposed = proposal?.let(::proposalView)
        fun view(
            state: PersonalVaultState, title: String, body: String, keep: String? = null, served: String? = null, use: String? = null,
            choices: List<PersonalChoiceView> = emptyList(), others: List<PersonalChoiceView> = emptyList(),
        ) = PersonalVaultView(state, title, body, keep, served, use, lookupFailed, choices, others, proposed, error)

        val change = live.engine.personalChange()
        fun servedLine(newName: String) = details?.let { d ->
            val holders = if (d.servedCoHolders.isEmpty()) "nobody else" else d.servedCoHolders.joinToString(", ") { "${it.displayName} (${it.role})" }
            "$newName, as reported by the server: ${describe(d.servedOrigin)} · also held by $holders."
        }
        publish(
            when (status) {
                Account.PersonalStatus.WITHHELD -> view(
                    PersonalVaultState.WITHHELD, "The server didn't send your personal-vault record this time.",
                    "This device kept the one it already had, so nothing changed. If this keeps happening, tell your admin.",
                )
                Account.PersonalStatus.UNREADABLE_CACHED -> {
                    val n = name(live, live.account.personalVaultId)
                    view(
                        PersonalVaultState.UNREADABLE_KEPT, "The server sent a personal-vault record this account can't read.",
                        "This device kept the one it already had ($n), so nothing changed. To repair the server's copy, choose $n again below (it asks for your master password), and tell your admin.",
                        others = own,
                    )
                }
                Account.PersonalStatus.PROPOSED -> {
                    if (change == null) {
                        null
                    } else {
                        val newName = details?.servedName ?: name(live, change.servedVaultId)
                        val designated = change.currentVaultId.takeIf { it.isNotEmpty() }?.let { details?.currentName ?: name(live, it) }
                        view(
                            PersonalVaultState.PROPOSED,
                            if (designated == null) "The server says your personal vault is $newName." else "Your account's personal vault is $designated, but the server sent $newName.",
                            if (designated == null) "This device hasn't confirmed it yet, so it uses no personal vault until you decide: new items have nowhere to go until then."
                            else "Another of your devices chose $designated, or the server sent an older record. This device uses no personal vault until you decide.",
                            keep = designated?.let { "Keep $it" }, served = servedLine(newName), use = details?.let { "Use $newName" }, others = own,
                        )
                    }
                }
                Account.PersonalStatus.CHANGED -> {
                    if (change == null) {
                        null
                    } else {
                        val newName = details?.servedName ?: name(live, change.servedVaultId)
                        val oldName = details?.currentName ?: name(live, change.currentVaultId)
                        view(
                            PersonalVaultState.CHANGED, "Your personal vault was changed from $oldName to $newName.",
                            "Another of your devices changed it, or the server sent an older record. This device still uses $oldName until you decide. If you didn't change it, keep $oldName (it asks for your master password) and tell your admin.",
                            keep = "Keep $oldName", served = servedLine(newName), use = details?.let { "Use $newName" },
                        )
                    }
                }
                Account.PersonalStatus.ABSENT -> view(
                    PersonalVaultState.UNCHOSEN, "Your personal vault isn't confirmed yet.",
                    "Until it is, new logins have nowhere to go. Which vault is your personal vault?",
                    choices = live.engine.personalVaultChoices.orEmpty().map { c ->
                        PersonalChoiceView(c.vaultId, "${c.name ?: "(unnamed)"} · ${c.itemCount} items", choiceDetail(live.engine.personalChoiceInfo(c.vaultId)))
                    },
                )
                else -> view(
                    PersonalVaultState.UNREADABLE, "Your personal vault isn't confirmed yet.",
                    "The server sent a personal-vault record this account can't read. Choose your personal vault below (it asks for your master password), and tell your admin.",
                    others = own,
                )
            },
        )
    }

    /**
     * Look up what the notice needs from the server: who else holds the vault the server names (a change or a
     * proposal), or each vault on offer (a first choice). A failure is said, and "use" stays unoffered.
     */
    suspend fun load(live: VaultSession.Unlocked) {
        try {
            when (live.account.personalStatus) {
                Account.PersonalStatus.PROPOSED, Account.PersonalStatus.CHANGED -> {
                    if (live.engine.personalChange() != null) details = live.engine.describePersonalChange()
                    lookupFailed = false
                }
                Account.PersonalStatus.ABSENT -> live.engine.personalVaultChoices?.takeIf { it.isNotEmpty() }?.let { live.engine.refreshPersonalChoiceDetails(it.map { c -> c.vaultId }) }
                Account.PersonalStatus.CONFIRMED, Account.PersonalStatus.WITHHELD -> {}
                else -> live.engine.redesignationChoices().takeIf { it.isNotEmpty() }?.let { live.engine.refreshPersonalChoiceDetails(it.map { v -> v.vaultId }) }
            }
        } catch (c: CancellationException) {
            throw c
        } catch (_: Throwable) {
            lookupFailed = true
        }
        render(live)
    }

    /** "Use <served>": the served vault becomes this device's personal vault. The core refuses until its co-holders loaded. */
    fun useServed(live: VaultSession.Unlocked): Boolean {
        error = runCatching { live.engine.acceptPersonalChange() }.exceptionOrNull()?.let { "Couldn't confirm. Try again." }
        if (error == null) {
            details = null
            changed()
        }
        render(live)
        return error == null
    }

    /**
     * Propose [vaultId] (a choice), or with null the vault this device or the account already has ("Keep"). It looks
     * up who else holds the vault and raises the confirmation; nothing is minted.
     */
    suspend fun propose(live: VaultSession.Unlocked, vaultId: String?): Boolean {
        error = null
        val keep = vaultId == null
        val target = vaultId ?: live.engine.personalChange()?.currentVaultId?.takeIf { it.isNotEmpty() }
        if (target == null) {
            render(live)
            return false
        }
        val status = live.account.personalStatus
        try {
            proposal = live.engine.proposePersonalVault(target)
            proposalKeeps = keep
            // Only a first designation (no record anywhere) goes without the password.
            needsReauth = status != Account.PersonalStatus.ABSENT
        } catch (c: CancellationException) {
            throw c
        } catch (_: Throwable) {
            proposal = null
            error = "Couldn't check who else holds that vault. Try again when you're connected."
        }
        render(live)
        return proposal != null
    }

    fun cancel(live: VaultSession.Unlocked) {
        runCatching { live.engine.cancelPersonalProposal() }
        proposal = null
        error = null
        render(live)
    }

    /** Confirm the raised proposal; [password] where the confirmation asked for it. Returns whether it was written. */
    suspend fun confirm(live: VaultSession.Unlocked, password: String?): Boolean {
        val p = proposal ?: return false
        val view = proposalView(p)
        if (view.needsPassword && password.isNullOrEmpty()) {
            error = "Enter your master password to confirm."
            render(live)
            return false
        }
        val failure = try {
            if (view.needsPassword) live.engine.redesignatePersonalVault(p, password!!) else live.engine.confirmPersonalVault(p, null)
            null
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            t
        }
        if (failure == null) {
            proposal = null
            details = null
            error = null
            changed()
        } else {
            error = when (failure) {
                is ReauthStaleSessionException -> HouseholdCopy.REAUTH_STALE_SESSION
                is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION
                else -> if (view.needsPassword) "Couldn't save that: wrong master password, or the server refused." else "Couldn't save that. If another device already chose, choose again below."
            }
            // A first designation that failed stays up for another try; a refused reauth keeps the dialog too.
        }
        render(live)
        return failure == null
    }
}
