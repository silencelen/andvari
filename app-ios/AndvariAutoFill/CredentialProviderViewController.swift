import AndvariCore
import AuthenticationServices
import UIKit

/// System AutoFill (design 2026-11-09, "AutoFill"). Fill only: this process never contacts the server and never
/// runs the password KDF. It reads the app's encrypted snapshot from the App Group, unlocks it with Face ID through
/// the same Secure Enclave key and gates as the app's quick unlock, hands iOS the one credential, and zeroes the keys.
final class CredentialProviderViewController: ASCredentialProviderViewController, UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate {
    private enum Mode {
        case list
        case oneTimeCodeList
        case single(recordIdentifier: String, oneTimeCode: Bool)
        case configuration
    }

    private let vault = IosAutofill()
    private var mode: Mode = .list
    private var hosts: [String] = []
    private var logins: [FillLogin] = []
    private var shown: [FillLogin] = []
    private var started = false
    /// The unlock in flight, so it is cancelled when the request ends first.
    private var unlocking: Task<Void, Never>?
    /// The request has been answered (completed or cancelled): nothing may answer it again.
    private var finished = false
    private var hostObserver: NSObjectProtocol?
    private var listTimeout: Timer?
    /// How long an unlocked list may stay up before the keys are dropped and the request is cancelled.
    private static let listLifetime: TimeInterval = 120

    private let message = UILabel()
    private let table = UITableView(frame: .zero, style: .insetGrouped)
    private let search = UISearchBar()

    // MARK: - Requests from iOS

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        mode = .list
        hosts = serviceIdentifiers.map(\.identifier)
    }

    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        mode = .oneTimeCodeList
        hosts = serviceIdentifiers.map(\.identifier)
    }

    /// Every fill needs Face ID, so there is never a credential without interaction.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        fail(.userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        // The site iOS is filling for: the record is completed only if it is still a login for that site.
        hosts = [credentialRequest.credentialIdentity.serviceIdentifier.identifier]
        guard let record = credentialRequest.credentialIdentity.recordIdentifier else {
            mode = .list
            return
        }
        var oneTimeCode = false
        if #available(iOS 18.0, *) {
            oneTimeCode = credentialRequest.type == .oneTimeCode
        }
        mode = .single(recordIdentifier: record, oneTimeCode: oneTimeCode)
    }

    override func prepareInterfaceForExtensionConfiguration() {
        mode = .configuration
    }

    /// iOS 26.2: the system offers to save a login to andvari. This process cannot reach the server and holds no
    /// key, so the login is sealed to the account's public key and queued for the app, which shows it before it is
    /// written. No unlock and no interface are needed for that.
    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest: ASSavePasswordRequest) {
        let credential = savePasswordRequest.credential
        let queued = vault.queueSave(
            id: savePasswordRequest.sessionID,
            site: savePasswordRequest.serviceIdentifier.identifier,
            username: credential.user,
            password: credential.password
        )
        if queued == .queued {
            extensionContext.completeSavePasswordRequest(completionHandler: nil)
        } else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
        }
    }

    // MARK: - View

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground

        let bar = UINavigationBar()
        let item = UINavigationItem(title: "andvari")
        item.leftBarButtonItem = UIBarButtonItem(systemItem: .cancel, primaryAction: UIAction { [weak self] _ in self?.fail(.userCanceled) })
        bar.items = [item]

        message.numberOfLines = 0
        message.textAlignment = .center
        message.textColor = .secondaryLabel
        message.font = .preferredFont(forTextStyle: .body)
        message.adjustsFontForContentSizeCategory = true

        search.placeholder = "Search logins"
        search.delegate = self
        search.autocapitalizationType = .none
        search.isHidden = true

        table.dataSource = self
        table.delegate = self
        table.isHidden = true

        let stack = UIStackView(arrangedSubviews: [bar, search, message, table])
        stack.axis = .vertical
        stack.setCustomSpacing(24, after: search)
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !started else { return }
        started = true
        // The app this sheet is over went to the background: the fill is over, and so is the unlock.
        hostObserver = NotificationCenter.default.addObserver(forName: .NSExtensionHostDidEnterBackground, object: nil, queue: .main) { [weak self] _ in
            self?.fail(.userCanceled)
        }
        start()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        end()
    }

    /// Stop everything that could still act: the unlock in flight, the timer, and the keys.
    private func end() {
        unlocking?.cancel()
        unlocking = nil
        listTimeout?.invalidate()
        listTimeout = nil
        if let hostObserver {
            NotificationCenter.default.removeObserver(hostObserver)
            self.hostObserver = nil
        }
        vault.close()
    }

    private func start() {
        if case .configuration = mode {
            show("andvari is ready to fill passwords. Turn on Face ID in andvari's Settings, and unlock the app once after signing in.")
            return
        }
        if let blocked = vault.availability() as? FillAvailability.OpenApp {
            show(blocked.message)
            return
        }
        unlocking = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let result = try await vault.unlock(reason: "Unlock andvari to fill")
                // The request ended while Face ID was up: the core kept nothing, and nothing is answered twice.
                guard !Task.isCancelled, !finished else { return }
                if let blocked = result as? FillUnlock.OpenApp {
                    show(blocked.message)
                } else if result is FillUnlock.Unlocked {
                    unlocked()
                } else {
                    fail(.userCanceled)
                }
            } catch {
                fail(.userCanceled)
            }
        }
    }

    private func unlocked() {
        switch mode {
        case let .single(record, oneTimeCode):
            // The suggestion named a record; fill it only if it is a login for the site being filled. Otherwise the
            // person picks from the list, where what matches this site is marked.
            if vault.matches(itemId: record, identifiers: hosts) {
                complete(itemId: record, oneTimeCode: oneTimeCode)
            } else {
                mode = oneTimeCode ? .oneTimeCodeList : .list
                unlocked()
            }
        case .oneTimeCodeList:
            logins = vault.logins(hosts: hosts).filter(\.hasTotp)
            showList()
        case .list, .configuration:
            logins = vault.logins(hosts: hosts)
            showList()
        }
    }

    private func showList() {
        shown = logins
        if logins.isEmpty {
            show("No logins to fill here yet. Add one in andvari.")
            return
        }
        message.isHidden = true
        search.isHidden = false
        table.isHidden = false
        table.reloadData()
        // An unlocked list does not stay up indefinitely with the keys in memory.
        listTimeout?.invalidate()
        listTimeout = Timer.scheduledTimer(withTimeInterval: Self.listLifetime, repeats: false) { [weak self] _ in
            self?.fail(.userCanceled)
        }
    }

    private func show(_ text: String) {
        table.isHidden = true
        search.isHidden = true
        message.isHidden = false
        message.text = text
    }

    // MARK: - Completing

    private func complete(itemId: String, oneTimeCode: Bool) {
        guard !finished else { return }
        defer { end() }
        if oneTimeCode {
            guard #available(iOS 18.0, *), let code = vault.oneTimeCode(itemId: itemId) else {
                fail(.credentialIdentityNotFound)
                return
            }
            finished = true
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
            return
        }
        guard let credential = vault.credential(itemId: itemId) else {
            fail(.credentialIdentityNotFound)
            return
        }
        finished = true
        extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: credential.username, password: credential.password))
    }

    private func fail(_ code: ASExtensionError.Code) {
        end()
        guard !finished else { return }
        finished = true
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    // MARK: - Table

    private var matching: [FillLogin] { shown.filter(\.matches) }
    private var others: [FillLogin] { shown.filter { !$0.matches } }

    private func rows(_ section: Int) -> [FillLogin] {
        matching.isEmpty ? others : (section == 0 ? matching : others)
    }

    func numberOfSections(in tableView: UITableView) -> Int {
        matching.isEmpty || others.isEmpty ? 1 : 2
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        rows(section).count
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        if matching.isEmpty { return "All logins" }
        return section == 0 ? "For this site" : "Other logins"
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "login") ?? UITableViewCell(style: .subtitle, reuseIdentifier: "login")
        let login = rows(indexPath.section)[indexPath.row]
        var content = cell.defaultContentConfiguration()
        content.text = login.name
        content.secondaryText = [login.username, login.host ?? ""].filter { !$0.isEmpty }.joined(separator: " · ")
        content.secondaryTextProperties.color = .secondaryLabel
        cell.contentConfiguration = content
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let login = rows(indexPath.section)[indexPath.row]
        var oneTimeCode = false
        if case .oneTimeCodeList = mode { oneTimeCode = true }
        complete(itemId: login.itemId, oneTimeCode: oneTimeCode)
    }

    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        shown = query.isEmpty ? logins : logins.filter {
            $0.name.lowercased().contains(query) || $0.username.lowercased().contains(query) || ($0.host ?? "").lowercased().contains(query)
        }
        table.reloadData()
    }
}
