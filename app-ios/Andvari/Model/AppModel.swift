import AndvariCore
import SwiftUI

/// The screen the controller names. `AppScreen` is a Kotlin enum, exported as a class with one static
/// member per entry.
enum Screen: Equatable {
    case loading
    case chooseServer
    case trustGate
    case welcome
    case unlock
    case recover
    case recoveryReveal
    case recoveryCapture
    case vault
    case upgradeRequired

    init(_ screen: AppScreen) {
        let screens: [(AppScreen, Screen)] = [
            (AppScreen.chooseServer, .chooseServer),
            (AppScreen.trustGate, .trustGate),
            (AppScreen.welcome, .welcome),
            (AppScreen.unlock, .unlock),
            (AppScreen.recover, .recover),
            (AppScreen.recoveryReveal, .recoveryReveal),
            (AppScreen.recoveryCapture, .recoveryCapture),
            (AppScreen.vault, .vault),
            (AppScreen.upgradeRequired, .upgradeRequired),
        ]
        self = screens.first { $0.0 == screen }?.1 ?? .loading
    }
}

/// What an action came to. `ActionResult` is a Kotlin sealed class, so its cases arrive as subclasses.
enum Outcome: Equatable {
    case ok
    case needsCode(wrongCode: Bool)
    case mismatch
    case otherServer(origin: String)
    case notDone(message: String?)
    case failed(message: String)
    /// The calling task was cancelled before the action answered.
    case cancelled

    init(_ result: ActionResult) {
        switch result {
        case is ActionResult.Ok:
            self = .ok
        case let needsCode as ActionResult.NeedsCode:
            self = .needsCode(wrongCode: needsCode.wrongCode)
        case is ActionResult.Mismatch:
            self = .mismatch
        case let other as ActionResult.OtherServer:
            self = .otherServer(origin: other.origin)
        case let notDone as ActionResult.NotDone:
            self = .notDone(message: notDone.message)
        case let failed as ActionResult.Failed:
            self = .failed(message: failed.message)
        default:
            self = .failed(message: Wording.genericFailure)
        }
    }

    /// The sentence to show in place, if any. Every message from the core is user-facing copy.
    var message: String? {
        switch self {
        case .notDone(let message): return message
        case .failed(let message): return message
        default: return nil
        }
    }
}

/// Owns the session controller and publishes its state to SwiftUI. The controller publishes on the main
/// thread and runs its actions there, so everything here is main-actor work.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var state: AppState
    /// The Trust Gate on screen was raised by an invite for another server, so enrolling there makes a new account.
    @Published private(set) var gateForInvite = false

    private let controller: IosSessionController
    /// What the system's suggestions were last built from; nil once cleared. Starts non-nil so a signed-out launch clears.
    private var suggestedKey: String? = ""
    private var endObservation: (() -> Void)?
    private var wasInBackground = false

    init() {
        let controller = IosSessionController()
        self.controller = controller
        state = controller.state
        let observation = controller.observe { [weak self] next in
            MainActor.assumeIsolated {
                self?.receive(next)
            }
        }
        endObservation = { observation.close() }
        controller.start()
        CredentialIdentities.publishProviderState()
    }

    private func receive(_ next: AppState) {
        if Screen(next.screen) != .trustGate {
            gateForInvite = false
        }
        state = next
        if let seconds = next.policy?.clipboardClearSeconds {
            Clipboard.lifetime = TimeInterval(seconds)
        }
        syncCredentialIdentities(next)
    }

    /// The system's AutoFill suggestions follow the unlocked vault and go when the account does. They hold hosts
    /// and usernames, never a password; the core returns none when the server forbids an offline cache.
    private func syncCredentialIdentities(_ next: AppState) {
        switch Screen(next.screen) {
        case .vault where next.query.isEmpty:
            // The account and the policy are part of the key: a policy that starts forbidding the offline cache, or
            // another account, rebuilds the suggestions even when the list looks the same (the core then returns none).
            let allowed = next.policy?.offlineCacheAllowed == true
            let rows = next.items.map { "\($0.itemId)|\($0.username ?? "")|\($0.host ?? "")|\($0.hasTotp)" }.joined(separator: "\n")
            let key = "\(next.accountEmail ?? "")|\(next.server ?? "")|\(allowed)\n\(rows)"
            guard key != suggestedKey else { return }
            suggestedKey = key
            CredentialIdentities.replace(controller.credentialIdentities())
        case .vault, .unlock, .recover, .recoveryReveal, .recoveryCapture, .loading:
            break
        case .welcome, .chooseServer, .trustGate, .upgradeRequired:
            // No session behind these screens (an unlock screen has one): nothing may stay suggested.
            guard next.accountEmail == nil, suggestedKey != nil else { return }
            suggestedKey = nil
            CredentialIdentities.clear()
        }
    }

    var screen: Screen { Screen(state.screen) }

    // MARK: - Lifecycle

    /// The vault locks when the app leaves the foreground; the idle check and a quiet sync run on return.
    func scenePhaseChanged(to phase: ScenePhase) {
        switch phase {
        case .background:
            wasInBackground = true
            controller.onBackground()
        case .active:
            if wasInBackground {
                wasInBackground = false
                controller.onForeground()
                CredentialIdentities.publishProviderState()
            }
        default:
            break
        }
    }

    /// The person touched or typed: the idle window starts again.
    func userActivity() {
        controller.userActivity()
    }

    /// Stop the controller: its work is cancelled and the vault locks.
    func close() {
        endObservation?()
        endObservation = nil
        controller.close()
    }

    // MARK: - Server

    func chooseServer(_ input: String) -> ServerChoice {
        controller.chooseServer(input: input)
    }

    /// An invite named another server: the same Trust Gate, which then also says enrolling makes a new account.
    func chooseServerForInvite(_ origin: String) -> ServerChoice {
        let choice = controller.chooseServer(input: origin)
        gateForInvite = choice is ServerChoice.NeedsGate
        return choice
    }

    func confirmTrustGate() async -> Outcome {
        await run { try await $0.confirmTrustGate() }
    }

    func cancelTrustGate() {
        controller.cancelTrustGate()
    }

    func changeServer() {
        controller.changeServer()
    }

    /// Back out of the server field: the server already chosen stays.
    func cancelChangeServer() {
        controller.cancelChangeServer()
    }

    // MARK: - Forgot the master password

    func openRecover() {
        controller.openRecover()
    }

    func cancelRecover() {
        controller.cancelRecover()
    }

    func recoverVerify(email: String, phrase: String) async -> Outcome {
        await run { try await $0.recoverVerify(email: email, phrase: phrase) }
    }

    func recoverCommit(newPassword: String) async -> Outcome {
        await run { try await $0.recoverCommit(newPassword: newPassword) }
    }

    // MARK: - Identity

    /// This account's identity code (32 hex digits), from the key this device holds. Nil while locked.
    func identityCode() -> String? {
        controller.identityCode()
    }

    func identityCodeFull() -> String? {
        controller.identityCodeFull()
    }

    func retryServer() async -> Outcome {
        await run { try await $0.retryServer() }
    }

    // MARK: - Sign-in and enroll

    func signIn(email: String, password: String, totp: String?) async -> Outcome {
        await run { try await $0.signIn(email: email, password: password, totp: totp) }
    }

    func enroll(_ form: EnrollForm) async -> Outcome {
        await run { try await $0.enroll(form: form) }
    }

    // MARK: - Recovery phrase

    func recoveryPhrase() -> String? {
        controller.recoveryPhrase()
    }

    func confirmRecoveryPhrase(_ typedBack: String) async -> Outcome {
        await run { try await $0.confirmRecoveryPhrase(typedBack: typedBack) }
    }

    func retryRecoveryCapture() async -> Outcome {
        await run { try await $0.retryRecoveryCapture() }
    }

    // MARK: - Unlock

    func unlock(password: String) async -> Outcome {
        await run { try await $0.unlock(password: password) }
    }

    /// The prompt's wording is the controller's.
    func unlockWithBiometrics() async -> Outcome {
        await run { try await $0.unlockWithBiometrics(reason: nil) }
    }

    func enableQuickUnlock() async -> Outcome {
        await run { try await $0.enableQuickUnlock(reason: nil) }
    }

    func disableQuickUnlock() {
        controller.disableQuickUnlock()
    }

    // MARK: - Vault

    func setQuery(_ query: String) {
        controller.setQuery(query: query)
    }

    func itemDetail(_ itemId: String) -> ItemDetail? {
        controller.itemDetail(itemId: itemId)
    }

    /// One secret, for an explicit reveal or copy. Callers keep it only as long as it is on screen.
    /// When each earlier password of a login was retired, newest first.
    func passwordHistory(_ itemId: String) -> [Date] {
        controller.passwordHistory(itemId: itemId).map { Date(timeIntervalSince1970: TimeInterval(truncating: $0) / 1000) }
    }

    /// One earlier password, by its place in `passwordHistory`.
    func previousPassword(_ itemId: String, _ index: Int) -> String? {
        controller.previousPassword(itemId: itemId, index: Int32(index))
    }

    /// What to say under a card number while it is typed: one that cannot be saved, or one that looks unusual.
    func cardNumberWarning(_ number: String) -> String? {
        controller.cardNumberWarning(number: number)
    }

    func revealSecret(_ itemId: String, _ field: SecretField) -> String? {
        controller.revealSecret(itemId: itemId, field: field)
    }

    func oneTimeCode(_ itemId: String) -> OneTimeCode? {
        controller.oneTimeCode(itemId: itemId)
    }

    /// [vaultId]: where a new item goes (nil: the personal vault); an edit stays in its vault.
    func saveLogin(itemId: String?, input: LoginInput, vaultId: String? = nil) async -> Outcome {
        await run { try await $0.saveLogin(itemId: itemId, input: input, vaultId: vaultId) }
    }

    func saveCard(itemId: String?, input: CardInput, vaultId: String? = nil) async -> Outcome {
        await run { try await $0.saveCard(itemId: itemId, input: input, vaultId: vaultId) }
    }

    func saveNote(itemId: String?, input: NoteInput, vaultId: String? = nil) async -> Outcome {
        await run { try await $0.saveNote(itemId: itemId, input: input, vaultId: vaultId) }
    }

    // MARK: - Shared vaults

    func openSharing() async -> Outcome {
        await run { try await $0.openSharing() }
    }

    func closeSharing() {
        controller.closeSharing()
    }

    func createSharedVault(_ name: String) async -> Outcome {
        await run { try await $0.createSharedVault(name: name) }
    }

    func renameSharedVault(_ vaultId: String, name: String) async -> Outcome {
        await run { try await $0.renameSharedVault(vaultId: vaultId, name: name) }
    }

    /// The core names it saveVaultItemsToPersonal: Kotlin/Native exports a name that starts with "copy" as doCopy….
    func copySharedVaultToPersonal(_ vaultId: String) async -> Outcome {
        await run { try await $0.saveVaultItemsToPersonal(vaultId: vaultId) }
    }

    func deleteSharedVault(_ vaultId: String, typedName: String) async -> Outcome {
        await run { try await $0.deleteSharedVault(vaultId: vaultId, typedName: typedName) }
    }

    func restoreDeletedVault(_ vaultId: String) async -> Outcome {
        await run { try await $0.restoreDeletedVault(vaultId: vaultId) }
    }

    func leaveSharedVault(_ vaultId: String) async -> Outcome {
        await run { try await $0.leaveSharedVault(vaultId: vaultId) }
    }

    // MARK: - Two-step sign-in

    func loadTwoStep() async -> Outcome {
        await run { try await $0.loadTwoStep() }
    }

    /// The master password proves it is the account's owner before a new code is set up.
    func beginTwoStep(password: String) async -> Outcome {
        await run { try await $0.beginTwoStep(password: password) }
    }

    /// The key being set up (shown once, to add to an authenticator); nil when none is.
    func twoStepSetup() -> TwoStepSetup? {
        controller.twoStepSetup()
    }

    func confirmTwoStep(code: String) async -> Outcome {
        await run { try await $0.confirmTwoStep(code: code) }
    }

    func disableTwoStep(code: String) async -> Outcome {
        await run { try await $0.disableTwoStep(code: code) }
    }

    func closeTwoStep() {
        controller.closeTwoStep()
    }

    // MARK: - Vaults

    func dismissVaultNotice(_ id: String) {
        controller.dismissVaultNotice(id: id)
    }

    /// Where a new item may go: the personal vault first, then the shared vaults this account can write.
    func newItemVaults() -> [VaultChoiceView] {
        // Kotlin/Native exports a name that starts with "new" as doNew… (Objective-C's method families), so the core
        // calls it vaultsForNewItems.
        controller.vaultsForNewItems()
    }

    /// The vaults an item can be moved or copied to.
    func moveTargets(_ itemId: String) -> [VaultChoiceView] {
        controller.moveTargets(itemId: itemId)
    }

    /// Whether the item can leave its vault; otherwise it can only be copied out.
    func canMoveOut(_ itemId: String) -> Bool {
        controller.canMoveOut(itemId: itemId)
    }

    /// The move or copy sheet closed without finishing: what an unfinished try kept goes.
    func cancelMove(_ itemId: String) {
        controller.cancelMove(itemId: itemId)
    }

    func moveOrCopyItem(_ itemId: String, to vaultId: String, move: Bool) async -> Outcome {
        await run { try await $0.moveOrCopyItem(itemId: itemId, targetVaultId: vaultId, move: move) }
    }

    // MARK: - Trash and history

    func openTrash() async -> Outcome {
        await run { try await $0.openTrash() }
    }

    func closeTrash() {
        controller.closeTrash()
    }

    func restoreFromTrash(_ itemId: String) async -> Outcome {
        await run { try await $0.restoreFromTrash(itemId: itemId) }
    }

    func purgeFromTrash(_ itemId: String) async -> Outcome {
        await run { try await $0.purgeFromTrash(itemId: itemId) }
    }

    func openItemHistory(_ itemId: String) async -> Outcome {
        await run { try await $0.openItemHistory(itemId: itemId) }
    }

    func closeItemHistory() {
        controller.closeItemHistory()
    }

    /// One earlier version's password, for an explicit Show. Held only while the history is open.
    func historyPassword(_ itemId: String, _ rev: Int64) -> String? {
        controller.historyPassword(itemId: itemId, rev: rev)
    }

    func restoreItemVersion(_ itemId: String, _ rev: Int64) async -> Outcome {
        await run { try await $0.restoreItemVersion(itemId: itemId, rev: rev) }
    }

    func deleteItem(_ itemId: String) async -> Outcome {
        await run { try await $0.deleteItem(itemId: itemId) }
    }

    // MARK: - Personal vault

    func retryPersonalVaultDetails() async -> Outcome {
        await run { try await $0.retryPersonalVaultDetails() }
    }

    /// "Use <the vault the server names>": offered only after who else holds it was loaded.
    func usePersonalVaultServed() -> Outcome {
        Outcome(controller.usePersonalVaultServed())
    }

    /// Propose a vault from the notice's choices, or with nil the one to keep; raises the confirmation.
    func proposePersonalVault(_ vaultId: String?) async -> Outcome {
        await run { try await $0.proposePersonalVault(vaultId: vaultId) }
    }

    func cancelPersonalVaultProposal() {
        controller.cancelPersonalVaultProposal()
    }

    func confirmPersonalVault(password: String?) async -> Outcome {
        await run { try await $0.confirmPersonalVault(password: password) }
    }

    // MARK: - Logins captured by the extensions

    /// The captured password, for the person to check before saving it.
    func pendingSavePassword(_ id: String) -> String? {
        controller.pendingSavePassword(id: id)
    }

    func confirmPendingSave(_ id: String) async -> Outcome {
        await run { try await $0.confirmPendingSave(id: id) }
    }

    func discardPendingSave(_ id: String) {
        controller.discardPendingSave(id: id)
    }

    /// Take back one login the app saved by itself at unlock.
    func undoAppliedSave(_ id: String) async -> Outcome {
        await run { try await $0.undoAppliedSave(id: id) }
    }

    func undoAllAppliedSaves() async -> Outcome {
        await run { try await $0.undoAllAppliedSaves() }
    }

    func dismissAppliedSaves() {
        controller.dismissAppliedSaves()
    }

    func refresh() async -> Outcome {
        await run { try await $0.refresh() }
    }

    func generatePassword(_ settings: GeneratorSettings) -> String {
        controller.generatePassword(settings: settings)
    }

    // MARK: - Session

    func lock() {
        controller.lock()
    }

    func signOut() async -> Outcome {
        await run { try await $0.signOut() }
    }

    func dismissError() {
        controller.dismissError()
    }

    func dismissNotice() {
        controller.dismissNotice()
    }

    /// Runs one suspend action. The controller throws only a cancellation; every other outcome is a result.
    private func run(_ action: (IosSessionController) async throws -> ActionResult?) async -> Outcome {
        do {
            guard let result = try await action(controller) else {
                return .failed(message: Wording.genericFailure)
            }
            return Outcome(result)
        } catch {
            return .cancelled
        }
    }
}
