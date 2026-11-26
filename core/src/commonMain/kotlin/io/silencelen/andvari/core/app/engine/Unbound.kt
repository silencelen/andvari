package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSettingsApi
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.ContactsApi
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveMemberRow
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OperatorApi
import io.silencelen.andvari.core.app.OperatorConsole
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PendingShareRow
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.QuotaLimits
import io.silencelen.andvari.core.app.RecoveryApi
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The parts of IF-3 for the signed-in account that later slices bind to the engine (contacts, links, shared vaults,
 * devices, recovery settings, password change, deletion). Until then every intent does nothing and says so:
 * [Trouble.STALE] when no account is open, [Trouble.FAILED] otherwise. No state is published for them.
 */
internal class Unbound(private val app: EngineAppApi) : ContactsApi, LinksApi, SharedVaultsApi, DevicesApi, RecoveryApi, AccountSettingsApi {
    private inline fun <reified R> no(): R where R : Enum<R>, R : io.silencelen.andvari.core.app.IntentResult =
        troubleOf(if (app.phase == io.silencelen.andvari.core.app.AppPhase.UNLOCKED) Trouble.FAILED else Trouble.STALE)

    // contacts
    override suspend fun openContacts(): PlainResult = no()
    override fun closeContacts() {}
    override suspend fun removeContact(contact: ContactRow): PlainResult = no()
    override suspend fun useOnThisDevice(prompt: AccountPrompt.NewPerson): PlainResult = no()
    override fun dontUseOnThisDevice(prompt: AccountPrompt.NewPerson) {}
    override suspend fun confirmOnThisDevice(contact: ContactRow): PlainResult = no()
    override suspend fun usePeople(prompt: AccountPrompt.PeopleList, userIds: List<String>): PlainResult = no()
    override fun peopleLater(prompt: AccountPrompt.PeopleList) {}
    override fun reviewPeople(screen: io.silencelen.andvari.core.app.ContactsScreen) {}
    override suspend fun openCompare(contact: ContactRow): PlainResult = no()
    override suspend fun openCompareForNewKey(prompt: AccountPrompt.KeyChanged): PlainResult = no()
    override fun closeCompare() {}
    override suspend fun submitComparison(screen: CompareScreen.Ready, digits: String): ComparisonResult = no()

    // links
    override suspend fun openLinks(): PlainResult = no()
    override fun closeLinks() {}
    override suspend fun createConnectLink(shares: List<ShareChoice>, minutes: Int): LinkCreateResult = no()
    override suspend fun createInvitation(minutes: Int): LinkCreateResult = no()
    override fun linkToShare(link: OwnLinkRow): String? = null
    override fun linkTimeLeftMs(link: OwnLinkRow): Long = 0L
    override suspend fun revokeLink(link: OwnLinkRow): PlainResult = no()
    override suspend fun releaseShare(share: PendingShareRow): VaultActionResult = no()
    override suspend fun openInvite(payload: String, source: PayloadSource): InviteResult = no()
    override fun acknowledgeKeyChange(prompt: OpenedInvite.KeyChanged) {}
    override suspend fun connect(prompt: OpenedInvite.Connect): ConnectResult = no()
    override suspend fun confirmOpenedGate(prompt: OpenedInvite.TrustGate): ServerResult = no()
    override fun dismissOpened() {}
    override suspend fun switchInstance(prompt: OpenedInvite.OtherInstance): ServerResult = no()
    override suspend fun switchInstanceConfirmed(prompt: OpenedInvite.OtherInstance, check: io.silencelen.andvari.core.app.SignOutCheck): ServerResult = no()
    override suspend fun retryConnection(prompt: AccountPrompt.ConnectionNotMade): ConnectResult = no()
    override fun dropConnection(prompt: AccountPrompt.ConnectionNotMade) {}
    override fun ownName(): String? = null
    override fun setOwnName(name: String): io.silencelen.andvari.core.app.OwnNameResult = io.silencelen.andvari.core.app.OwnNameResult.STALE

    // shared vaults
    override suspend fun createVault(name: String): VaultActionResult = no()
    override suspend fun renameVault(vault: SharedVaultRow, name: String): VaultActionResult = no()
    override suspend fun openMembers(vault: SharedVaultRow): VaultActionResult = no()
    override fun closeMembers() {}
    override suspend fun addMember(screen: MembersScreen, contact: ContactRow, role: MemberRole): VaultActionResult = no()
    override suspend fun confirmUncomparedShare(warning: UncomparedShareWarning): VaultActionResult = no()
    override fun cancelUncomparedShare(warning: UncomparedShareWarning) {}
    override suspend fun changeRole(member: MemberRow, role: MemberRole): VaultActionResult = no()
    override suspend fun removeMember(member: MemberRow): VaultActionResult = no()
    override suspend fun leaveVault(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun offerOwnership(member: MemberRow): VaultActionResult = no()
    override suspend fun cancelOffer(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun acceptOwnership(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun deleteVault(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun restoreVault(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun restoreDeletedVault(vault: io.silencelen.andvari.core.app.DeletedVaultView): VaultActionResult = no()
    override suspend fun acceptIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = no()
    override suspend fun declineIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = no()
    override suspend fun saveItemsElsewhere(vault: SharedVaultRow, toVaultId: String?): VaultActionResult = no()
    override fun removeFromThisDevice(vault: SharedVaultRow) {}
    override suspend fun openMoveEverything(vault: SharedVaultRow): VaultActionResult = no()
    override suspend fun openMoveEverythingRemoving(member: io.silencelen.andvari.core.app.MemberRow): VaultActionResult = no()
    override fun closeMoveEverything() {}
    override fun unfinishedMoveLater(move: io.silencelen.andvari.core.app.UnfinishedVaultMove) {}
    override suspend fun bringLateIntoMove(notice: io.silencelen.andvari.core.app.MoveStoredNotice): VaultActionResult = no()
    override fun dismissMoveStored(notice: io.silencelen.andvari.core.app.MoveStoredNotice) {}
    override fun tickMember(screen: MoveEverythingScreen, member: MoveMemberRow, ticked: Boolean) {}
    override suspend fun moveEverything(screen: MoveEverythingScreen, name: String): VaultActionResult = no()

    // devices
    override suspend fun openDevices(): PlainResult = no()
    override fun closeDevices() {}
    override suspend fun revokeDevice(device: DeviceRow, password: String): ProofResult = no()
    override suspend fun setRequireLink(enabled: Boolean, password: String): ProofResult = no()
    override suspend fun startDeviceLink(): PlainResult = no()
    override fun deviceLinkToShow(screen: DeviceLinkHost.Shown): String? = null
    override fun deviceLinkTimeLeftMs(): Long = 0L
    override suspend fun submitDeviceDigits(screen: DeviceLinkHost.TypeDigits, digits: String): DigitsResult = no()
    override suspend fun approveWithPassword(screen: DeviceLinkHost.Approvable, password: String): ProofResult = no()
    override suspend fun approveWithBiometrics(screen: DeviceLinkHost.Approvable, reason: String?): ProofResult = no()
    override suspend fun cancelDeviceLink(): PlainResult = no()
    override fun dismissDeviceLink() {}

    // recovery settings
    override suspend fun openRecovery(): PlainResult = no()
    override fun closeRecovery() {}
    override fun reviewOperatorRecovery(screen: RecoveryScreen) {}
    override suspend fun turnOnOperatorRecovery(warning: OperatorRecoveryWarning, understood: Boolean, password: String): RecoveryChangeResult = no()
    override fun keepRecoveryPrivate(warning: OperatorRecoveryWarning) {}
    override suspend fun turnOffOperatorRecovery(screen: RecoveryScreen, password: String): RecoveryChangeResult = no()
    override suspend fun makeKit(password: String): RecoveryChangeResult = no()
    override suspend fun cancelRecoveryRequest(request: RecoveryRequestRow): PlainResult = no()
    override fun recoveryRequestWasMe(prompt: AccountPrompt.RecoveryRequest) {}
    override suspend fun answerRecoveryKeyChanged(prompt: AccountPrompt.RecoveryKeyChanged, keep: Boolean, password: String): RecoveryChangeResult = no()
    override fun recoveryKeyChangedLater(prompt: AccountPrompt.RecoveryKeyChanged) {}
    override suspend fun answerKeepOperatorRecovery(prompt: AccountPrompt.KeepOperatorRecovery, keep: Boolean, password: String): RecoveryChangeResult = no()
    override fun keepOperatorRecoveryNotNow(prompt: AccountPrompt.KeepOperatorRecovery) {}

    // bound: the prompt for a new kit after a followed move (making the kit itself is not)
    override fun kitAfterMoveLater(prompt: io.silencelen.andvari.core.app.KitAfterMovePrompt) = app.kitAfterMoveLater(prompt)

    // bound: quick unlock
    override suspend fun turnOnQuickUnlock(setting: io.silencelen.andvari.core.app.QuickUnlockSetting) = app.turnOnQuickUnlock(setting)
    override fun turnOffQuickUnlock(setting: io.silencelen.andvari.core.app.QuickUnlockSetting) = app.turnOffQuickUnlock(setting)
    override fun quickUnlockNotNow(setting: io.silencelen.andvari.core.app.QuickUnlockSetting) = app.quickUnlockNotNow(setting)

    // bound: two-step sign-in (EngineTwoStep over the engine's WireTwoStep)
    override suspend fun openTwoStep(): PlainResult = app.twoStepFlow.openTwoStep()
    override fun closeTwoStep() = app.twoStepFlow.closeTwoStep()
    override suspend fun startTwoStep(screen: io.silencelen.andvari.core.app.TwoStepScreen, password: String) = app.twoStepFlow.startTwoStep(screen, password)
    override fun twoStepKey(enrolment: io.silencelen.andvari.core.app.TwoStepEnrolment) = app.twoStepFlow.twoStepKey(enrolment)
    override suspend fun confirmTwoStep(enrolment: io.silencelen.andvari.core.app.TwoStepEnrolment, code: String) = app.twoStepFlow.confirmTwoStep(enrolment, code)
    override suspend fun turnOffTwoStep(screen: io.silencelen.andvari.core.app.TwoStepScreen, code: String) = app.twoStepFlow.turnOffTwoStep(screen, code)
    override suspend fun turnOffTwoStepWithPassword(screen: io.silencelen.andvari.core.app.TwoStepScreen, code: String, password: String) =
        app.twoStepFlow.turnOffTwoStepWithPassword(screen, code, password)
    override suspend fun replaceTwoStepKey(screen: io.silencelen.andvari.core.app.TwoStepScreen, code: String, password: String) =
        app.twoStepFlow.replaceTwoStepKey(screen, code, password)

    // bound: the master password (EngineAccountSettings)
    override suspend fun changeMasterPassword(current: String, replacement: String): PasswordChangeResult =
        app.accountSettingsPart.changeMasterPassword(current, replacement)

    // settings

    // bound: account deletion (EngineAccountSettings over the engine's WireAccountDeletion)
    override suspend fun openDeletion(): PlainResult = app.accountSettingsPart.openDeletion()
    override fun closeDeletion() = app.accountSettingsPart.closeDeletion()
    override suspend fun deleteAccount(screen: DeletionScreen, typedEmail: String, password: String, code: String?): DeletionResult =
        app.accountSettingsPart.deleteAccount(screen, typedEmail, password, code)
    override suspend fun checkDeletion(screen: DeletionScreen): PlainResult = app.accountSettingsPart.checkDeletion(screen)
}

/** The operator views, bound in a later slice: no console, and every intent answers [Trouble.FAILED]. */
internal object UnboundOperator : OperatorApi {
    private val flow = MutableStateFlow<OperatorConsole?>(null)
    private fun no(): OperatorResult = troubleOf(Trouble.FAILED)

    override val console: OperatorConsole? get() = null
    override val consoles: StateFlow<OperatorConsole?> get() = flow
    override fun observeConsole(listener: (OperatorConsole?) -> Unit): Subscription {
        listener(null)
        return object : Subscription {
            override fun close() {}
        }
    }
    override suspend fun openConsole(): OperatorResult = no()
    override fun closeConsole() {}
    override suspend fun refreshConsole(): OperatorResult = no()
    override suspend fun finishServerSetup(password: String): OperatorResult = no()
    override suspend fun disableAccount(userId: String, why: DisableWhy, password: String): OperatorResult = no()
    override suspend fun enableAccount(userId: String, password: String): OperatorResult = no()
    override suspend fun deleteAccount(userId: String, password: String): OperatorResult = no()
    override suspend fun deleteAccountFor(userId: String, why: io.silencelen.andvari.core.app.OperatorDeleteWhy, password: String): OperatorResult = no()
    override suspend fun openAccountDevices(userId: String): OperatorResult = no()
    override fun closeAccountDevices() {}
    override suspend fun revokeAccountDevice(deviceId: String, password: String): OperatorResult = no()
    override suspend fun setAccountQuota(userId: String, limits: QuotaLimits, password: String): OperatorResult = no()
    override suspend fun savePolicy(policy: AdminPolicy, password: String): OperatorResult = no()
    override suspend fun loadAudit(sinceMs: Long, type: String?, userId: String?): OperatorResult = no()
    override suspend fun downloadEscrow(userId: String, password: String): OperatorResult = no()
    override fun takeEscrow(): AdminEscrowResponse? = null
    override suspend fun fulfilRecovery(requestId: String, sealedAnswer: String, password: String): OperatorResult = no()
    override suspend fun renameInstance(name: String, password: String): OperatorResult = no()
    override suspend fun moveInstance(origin: String, password: String): OperatorResult = no()
    override suspend fun changeRecoveryKey(recoveryFingerprint: String, rotationStatement: String?, password: String): OperatorResult = no()
    override suspend fun removeRecoveryKey(password: String): OperatorResult = no()
}
