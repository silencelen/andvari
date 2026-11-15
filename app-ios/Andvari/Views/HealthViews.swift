import AndvariCore
import SafariServices
import SwiftUI

/// Vault health (the Android app's screen, design 2026-08-23): weak and reused passwords, known breaches, copies of the
/// same account, and how long since each login was confirmed to still work. Every count, group and refusal comes from
/// core; this shows them. A breach check sends the server only the first 5 characters of each password's hash. andvari
/// never tries a password anywhere: a person signs in at the site themselves and says what happened.
struct VaultHealthView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.isPresented) private var isPresented
    @State private var tab = HealthTab.passwords
    @State private var merging: DuplicateClusterView?
    @State private var keeping: KeepChoice?
    @State private var refusal: String?
    @State private var openedItem: String?
    @State private var renewing: RenewTarget?
    /// What the run's offer asked for, done once the run's sheet has gone: one presentation at a time.
    @State private var afterRun: AfterRun?

    var body: some View {
        List {
            if let health = model.state.health {
                tilesSection(health.tiles)
                if let message = health.message {
                    Section {
                        HStack(alignment: .top, spacing: 10) {
                            Text(message)
                                .font(.subheadline)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Button("Dismiss") {
                                model.dismissHealthMessage()
                            }
                            .font(.subheadline)
                            .buttonStyle(.borderless)
                        }
                    }
                    .listRowBackground(Palette.raised)
                }
                if health.run == nil {
                    HealthOffers(health: health, open: { openedItem = $0 }, renew: { renewing = RenewTarget(id: $0) })
                }
                Section {
                    Picker("Show", selection: $tab) {
                        ForEach(HealthTab.allCases) { tab in
                            Text(tab.title).tag(tab)
                        }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                }
                switch tab {
                case .passwords:
                    passwordsSection(health)
                case .duplicates:
                    duplicatesSections(health)
                case .checked:
                    checkedSections(health)
                }
            } else {
                Section {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("Vault health")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                scanButton
            }
        }
        .onAppear {
            if model.state.health == nil { model.openHealth() } else { model.refreshHealth() }
        }
        .onDisappear {
            // An item opened from here is pushed over this screen, which stays open until it leaves the stack itself.
            if !isPresented { model.closeHealth() }
        }
        .navigationDestination(item: $openedItem) { itemId in
            ItemDetailView(itemId: itemId)
        }
        .sheet(isPresented: running, onDismiss: {
            switch afterRun {
            case .open(let itemId): openedItem = itemId
            case .renew(let itemId): renewing = RenewTarget(id: itemId)
            case nil: break
            }
            afterRun = nil
        }) {
            CheckRunSheet(open: { afterRun = .open($0) }, renew: { afterRun = .renew($0) })
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .sheet(item: $renewing, onDismiss: {
            model.closeAttachmentDraft()
            model.refreshHealth()
        }) { target in
            LoginEditorView(itemId: target.id, generateOnOpen: true)
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .confirmationDialog("Merge these copies?", isPresented: mergeAsked, titleVisibility: .visible, presenting: merging) { cluster in
            Button("Merge") {
                Task { _ = await model.mergeDuplicates(cluster.signature) }
            }
        } message: { cluster in
            Text(cluster.mergeConfirm ?? "")
        }
        .confirmationDialog("Keep this copy?", isPresented: keepAsked, titleVisibility: .visible, presenting: keeping) { choice in
            Button("Keep it") {
                Task { _ = await model.keepDuplicate(choice.signature, keep: choice.id) }
            }
        } message: { choice in
            Text(choice.detail)
        }
        .alert("Can't keep that copy here", isPresented: refusalShown) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(refusal ?? "")
        }
    }

    private var running: Binding<Bool> {
        Binding(get: { model.state.health?.run != nil }, set: { if !$0 { model.stopCheckRun() } })
    }

    private var mergeAsked: Binding<Bool> {
        Binding(get: { merging != nil }, set: { if !$0 { merging = nil } })
    }

    private var keepAsked: Binding<Bool> {
        Binding(get: { keeping != nil }, set: { if !$0 { keeping = nil } })
    }

    private var refusalShown: Binding<Bool> {
        Binding(get: { refusal != nil }, set: { if !$0 { refusal = nil } })
    }

    @ViewBuilder
    private var scanButton: some View {
        if let scan = model.state.health?.scan {
            HStack(spacing: 6) {
                ProgressView()
                Text("\(scan.done) of \(scan.total)")
                    .font(.footnote)
                    .monospacedDigit()
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Checking for breaches, \(scan.done) of \(scan.total)")
        } else {
            Button(model.state.health?.scanned == true ? "Check again" : "Check breaches") {
                Task { _ = await model.checkBreaches() }
            }
            .disabled(model.state.health?.passwords.isEmpty ?? true)
        }
    }

    // MARK: - The counts

    private func tilesSection(_ tiles: HealthTilesView) -> some View {
        Section {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 92), spacing: 8)], spacing: 8) {
                HealthTile(label: "Logins", value: "\(tiles.logins)", tone: .neutral)
                HealthTile(label: "Weak", value: "\(tiles.weak)", tone: tiles.weak > 0 ? .bad : .good)
                HealthTile(label: "Reused", value: "\(tiles.reused)", tone: tiles.reused > 0 ? .bad : .good)
                HealthTile(
                    label: "Breached",
                    value: tiles.breached.map { "\($0.intValue)" } ?? "–",
                    // A count from an incomplete check is real when it is above zero, but its zero is no verdict.
                    tone: breachedTone(tiles),
                    hint: tiles.breachedHint
                )
                HealthTile(label: "Duplicates", value: "\(tiles.duplicates)", tone: tiles.duplicates > 0 ? .bad : .good)
                HealthTile(label: "Unchecked", value: "\(tiles.unchecked)", tone: tiles.unchecked > 0 ? .bad : .good)
                HealthTile(label: "Failing", value: "\(tiles.failing)", tone: tiles.failing > 0 ? .bad : .good)
            }
            .padding(.vertical, 4)
        } footer: {
            Text("A breach check sends your server only the first 5 characters of each password's SHA-1 hash; the match is made on this iPhone.")
        }
        .listRowBackground(Color.clear)
    }

    private func breachedTone(_ tiles: HealthTilesView) -> HealthTile.Tone {
        guard let breached = tiles.breached?.intValue else { return .neutral }
        if breached > 0 { return .bad }
        return tiles.breachedHint == nil ? .good : .neutral
    }

    // MARK: - Passwords

    @ViewBuilder
    private func passwordsSection(_ health: HealthView) -> some View {
        Section {
            if health.passwords.isEmpty {
                Text("No logins with passwords yet: nothing to assess.")
                    .foregroundStyle(Palette.inkDim)
            }
            ForEach(health.passwords, id: \.itemId) { row in
                NavigationLink {
                    ItemDetailView(itemId: row.itemId)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(row.name)
                            .foregroundStyle(Palette.ink)
                            .lineLimit(1)
                        Text(strengthLine(row))
                            .font(.footnote)
                            .foregroundStyle(row.weak || row.reused > 0 ? Palette.danger : Palette.inkDim)
                        Text(breachLine(row))
                            .font(.footnote)
                            .foregroundStyle((row.breaches?.int64Value ?? 0) > 0 ? Palette.danger : Palette.inkDim)
                    }
                    .padding(.vertical, 2)
                }
            }
        } header: {
            Text("Passwords")
        }
        .listRowBackground(Palette.raised)
    }

    private func strengthLine(_ row: HealthPasswordView) -> String {
        var parts = ["Strength: \(row.strength)"]
        if row.reused > 0 { parts.append(row.reused == 1 ? "reused in 1 other login" : "reused in \(row.reused) other logins") }
        if row.hasTotp { parts.append("two-step code saved") }
        return parts.joined(separator: " · ")
    }

    private func breachLine(_ row: HealthPasswordView) -> String {
        guard let count = row.breaches?.int64Value else { return "Breaches: no verdict" }
        return count > 0 ? "Breaches: found \(count) times" : "Breaches: none found"
    }

    // MARK: - Duplicates

    @ViewBuilder
    private func duplicatesSections(_ health: HealthView) -> some View {
        Section {
            if health.duplicates.isEmpty {
                Text("No duplicate copies: every account is saved once.")
                    .foregroundStyle(Palette.inkDim)
            }
            ForEach(health.duplicates, id: \.signature) { cluster in
                clusterRow(cluster)
            }
        } header: {
            Text("Copies of the same account")
        } footer: {
            Text("Copies in different vaults are listed but never merged here: removing one would take it off every member's devices.")
        }
        .listRowBackground(Palette.raised)
        if !health.notDuplicates.isEmpty {
            Section {
                ForEach(health.notDuplicates, id: \.signature) { cluster in
                    HStack {
                        Text(cluster.sites)
                            .font(.subheadline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button("Put back") {
                            Task { _ = await model.restoreDuplicates(cluster.signature) }
                        }
                        .buttonStyle(.borderless)
                        .disabled(model.state.busy)
                    }
                }
            } header: {
                Text("Marked not duplicates")
            }
            .listRowBackground(Palette.raised)
        }
    }

    private func clusterRow(_ cluster: DuplicateClusterView) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(cluster.sites)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.ink)
            Text(cluster.exact ? "The same password on every copy." : "The same account with different passwords: one of them is out of date. Sign in to find the one that works, then keep it.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(cluster.members, id: \.itemId) { member in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(member.name)
                            .font(.subheadline)
                            .lineLimit(1)
                        Text((member.username.isEmpty ? "No username" : member.username) + " · in “\(member.vaultName)”")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                            .lineLimit(1)
                    }
                    Spacer(minLength: 8)
                    if let detail = member.keepConfirm {
                        Button("Keep this") {
                            if let why = member.keepRefusal {
                                refusal = why
                            } else {
                                keeping = KeepChoice(id: member.itemId, signature: cluster.signature, detail: detail)
                            }
                        }
                        .font(.footnote)
                        .buttonStyle(.borderless)
                        .disabled(model.state.busy)
                    }
                }
            }
            if let why = cluster.mergeRefusal {
                Text(why)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 20) {
                if cluster.mergeConfirm != nil {
                    Button("Merge…") {
                        merging = cluster
                    }
                    .font(.subheadline.weight(.semibold))
                }
                Button("Not duplicates") {
                    Task { _ = await model.markNotDuplicates(cluster.signature) }
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Checked

    @ViewBuilder
    private func checkedSections(_ health: HealthView) -> some View {
        Section {
            let never = health.staleness.filter(\.neverChecked).count
            Button(never == 1 ? "Check the 1 never checked" : "Check the \(never) never checked") {
                model.startCheckRun(neverCheckedOnly: true)
            }
            .disabled(never == 0)
            Button("Check all, worst first") {
                model.startCheckRun(neverCheckedOnly: false)
            }
            .disabled(health.staleness.isEmpty)
            Toggle("Show snoozed", isOn: snoozedShown)
        } footer: {
            Text("A check is you signing in at the site and saying what happened. andvari never tries a password itself, and changes nothing at the site.")
        }
        .listRowBackground(Palette.raised)
        Section {
            if health.staleness.isEmpty {
                Text(health.allSnoozed ? "Every login is snoozed right now: show snoozed to see them, or bring one back early." : "No logins to check yet.")
                    .foregroundStyle(Palette.inkDim)
            }
            ForEach(health.staleness, id: \.itemId) { row in
                VStack(alignment: .leading, spacing: 3) {
                    NavigationLink {
                        ItemDetailView(itemId: row.itemId)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.name)
                                .foregroundStyle(Palette.ink)
                                .lineLimit(1)
                            Text(row.state)
                                .font(.footnote)
                                .foregroundStyle(row.failing ? Palette.danger : Palette.inkDim)
                            Text(row.dates)
                                .font(.footnote)
                                .foregroundStyle(Palette.inkFaint)
                        }
                    }
                    if row.snoozed {
                        Button("Bring back now") {
                            Task { _ = await model.unsnoozeLogin(row.itemId) }
                        }
                        .font(.footnote)
                        .buttonStyle(.borderless)
                        .disabled(model.state.busy)
                    } else {
                        Button("Check") {
                            model.checkLogin(row.itemId)
                        }
                        .font(.footnote)
                        .buttonStyle(.borderless)
                        .disabled(model.state.busy)
                    }
                }
                .padding(.vertical, 2)
            }
        } header: {
            Text("Worst first")
        }
        .listRowBackground(Palette.raised)
    }

    private var snoozedShown: Binding<Bool> {
        Binding(get: { model.state.health?.showSnoozed ?? false }, set: { model.setHealthShowSnoozed($0) })
    }
}

enum HealthTab: String, CaseIterable, Identifiable {
    case passwords
    case duplicates
    case checked

    var id: String { rawValue }

    var title: String {
        switch self {
        case .passwords: return "Passwords"
        case .duplicates: return "Duplicates"
        case .checked: return "Checked"
        }
    }
}

private struct KeepChoice: Identifiable {
    /// The copy to keep.
    let id: String
    let signature: String
    let detail: String
}

private struct RenewTarget: Identifiable {
    let id: String
}

private enum AfterRun {
    case open(String)
    case renew(String)
}

/// One count at the top. What its number can't say by itself (no verdict yet, an incomplete check) is said in words too.
private struct HealthTile: View {
    enum Tone { case good, bad, neutral }

    let label: String
    let value: String
    let tone: Tone
    var hint: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.title3.weight(.semibold))
                .monospacedDigit()
                .foregroundStyle(tone == .bad ? Palette.danger : (tone == .good ? Palette.ok : Palette.inkDim))
            Text(hint.map { "\(label) · \($0)" } ?? label)
                .font(.caption)
                .foregroundStyle(Palette.inkDim)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Palette.raised, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(hint.map { "\(label): \(value), \($0)" } ?? "\(label): \(value)")
    }
}

/// The offer a verdict leaves (it names the login: the run may have moved on): a login marked as gone can go to the
/// trash, and one that refused its password can be opened or given a new password. Never done without the tap.
private struct HealthOffers: View {
    let health: HealthView
    let open: (String) -> Void
    let renew: (String) -> Void

    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let offer = health.offerDelete {
            Section {
                Text("“\(offer.name)” is marked as gone. Move it to the trash?")
                    .font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 20) {
                    Button("Move to the trash", role: .destructive) {
                        Task { _ = await model.trashGoneLogin() }
                    }
                    Button("Keep it") {
                        model.keepGoneLogin()
                    }
                }
                .font(.subheadline)
                .buttonStyle(.borderless)
                .disabled(model.state.busy)
            }
            .listRowBackground(Palette.raised)
        }
        if let offer = health.offerBad {
            Section {
                Text("“\(offer.name)” is marked as having the wrong password. Change it?")
                    .font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 10) {
                    Button("Open the login") {
                        model.answerBadOffer(opening: true)
                        open(offer.itemId)
                    }
                    Button("Give it a new password") {
                        model.answerBadOffer(opening: true)
                        renew(offer.itemId)
                    }
                    Button("Not now") {
                        model.answerBadOffer(opening: false)
                    }
                }
                .font(.subheadline)
                .buttonStyle(.borderless)
            }
            .listRowBackground(Palette.raised)
        }
    }
}

/// The check run (design §5): one login at a time. The person opens the site, signs in themselves (andvari's AutoFill
/// works in the page shown here), and says what happened; only that verdict is written. Skip writes nothing.
private struct CheckRunSheet: View {
    let open: (String) -> Void
    let renew: (String) -> Void

    @EnvironmentObject private var model: AppModel
    @State private var site: SiteLink?
    @State private var copied: String?

    var body: some View {
        NavigationStack {
            Form {
                if let health = model.state.health, let run = health.run {
                    Section {
                        Text(run.name)
                            .font(.headline)
                        Text(run.username.isEmpty ? "No username" : run.username)
                            .font(.subheadline)
                            .foregroundStyle(Palette.inkDim)
                        if let message = health.message {
                            InlineMessage(text: message)
                        }
                    } footer: {
                        Text("Open the site and sign in yourself, then say what happened.")
                    }
                    .listRowBackground(Palette.raised)
                    Section {
                        if !run.username.isEmpty {
                            Button("Copy username") {
                                Clipboard.copy(run.username)
                                copied = "Username copied"
                            }
                        }
                        if run.hasPassword {
                            Button("Copy password") {
                                guard let password = model.revealSecret(run.itemId, .password) else { return }
                                Clipboard.copy(password)
                                copied = "Password copied"
                            }
                        }
                        if let address = run.site, let url = SiteLink.url(address) {
                            Button("Open the site") {
                                site = SiteLink(url: url)
                            }
                        } else {
                            Text("No saved site to open.")
                                .foregroundStyle(Palette.inkDim)
                        }
                        if let copied {
                            Text(copied)
                                .font(.footnote)
                                .foregroundStyle(Palette.inkDim)
                        }
                    }
                    .listRowBackground(Palette.raised)
                    Section {
                        verdict("It worked", "ok")
                        verdict("It refused the password", "bad")
                        verdict("The account is gone", "gone")
                        verdict("I couldn't finish (ask again in 30 days)", "blocked")
                    } header: {
                        Text("What happened?")
                    }
                    .listRowBackground(Palette.raised)
                    // Taking the offer ends the run, which takes this sheet away; the login opens once it has gone.
                    HealthOffers(health: health, open: open, renew: renew)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Stop") {
                        model.stopCheckRun()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Skip") {
                        copied = nil
                        model.skipCheck()
                    }
                    .disabled(model.state.busy)
                }
            }
            .sheet(item: $site) { link in
                SafariPage(url: link.url)
                    .ignoresSafeArea()
            }
        }
    }

    private var title: String {
        guard let run = model.state.health?.run else { return "Check" }
        return "Check \(run.position) of \(run.total)"
    }

    private func verdict(_ label: String, _ result: String) -> some View {
        Button(label) {
            guard let itemId = model.state.health?.run?.itemId else { return }
            copied = nil
            Task { _ = await model.recordCheck(itemId, result: result) }
        }
        .disabled(model.state.busy)
    }
}

/// A saved site, opened in a Safari page inside the app: leaving for Safari itself would lock the vault.
private struct SiteLink: Identifiable {
    let id = UUID()
    let url: URL

    /// Only a web address is opened; one saved without a scheme is taken as https.
    static func url(_ address: String) -> URL? {
        let text = address.contains("://") ? address : "https://" + address
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http", url.host != nil else { return nil }
        return url
    }
}

private struct SafariPage: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> SFSafariViewController {
        let configuration = SFSafariViewController.Configuration()
        configuration.entersReaderIfAvailable = false
        return SFSafariViewController(url: url, configuration: configuration)
    }

    func updateUIViewController(_ controller: SFSafariViewController, context: Context) {}
}
