import AndvariCore
import AVFoundation
import CoreImage.CIFilterBuiltins
import SwiftUI
import VisionKit

/// One shared vault's members (spec 03 §10): who the server lists, and whether this device verified each of them by
/// comparing identity codes (root cause A §7.2). The owner adds someone once codes were compared with them, changes a
/// member's role, removes members, offers to make a member the owner (spec 03 §11) and shares the vault again with
/// members still on the older kind of sharing (§8.2 step 4); anyone else sees the list and can verify the people in it.
struct VaultMembersView: View {
    let vaultId: String

    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var message: String?
    @State private var email = ""
    @State private var role = "writer"
    @State private var removing: MemberView?
    @State private var handingOver: MemberView?
    @State private var resharing: LegacyGrantView?

    var body: some View {
        Form {
            if let members {
                listSection(members)
                if let offer = members.offer {
                    offerSection(offer, vaultName: members.vaultName)
                }
                if members.owner && !members.canAdd {
                    Section {
                        OwnershipConfirmRows(vaultId: members.vaultId, vaultName: members.vaultName)
                    } header: {
                        Text("You own “\(members.vaultName)”?")
                    }
                    .listRowBackground(Palette.raised)
                }
                if members.canAdd && !members.legacy.isEmpty {
                    legacySection(members)
                }
                if members.canAdd {
                    addSection(members)
                }
            } else if loading {
                Section {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                .listRowBackground(Color.clear)
            }
            if let message {
                Section {
                    InlineMessage(text: message)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("Members")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.openMembers(vaultId)
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onDisappear {
            model.closeMembers()
        }
        .sheet(isPresented: verifying) {
            VerifySheet()
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .confirmationDialog("Remove \(removing?.name ?? "")?", isPresented: removeAsked, titleVisibility: .visible, presenting: removing) { member in
            Button("Remove \(member.name)", role: .destructive) {
                act { await model.removeMember(member.userId) }
            }
        } message: { _ in
            Text("They lose access to this vault on all their devices. What they already saw they may have kept: the vault's key is not changed, so change any password that matters at its website too.")
        }
        .confirmationDialog("Make \(handingOver?.name ?? "") the owner?", isPresented: handOverAsked, titleVisibility: .visible, presenting: handingOver) { member in
            Button("Ask \(member.name) to take over") {
                act { await model.offerOwnership(member.userId) }
            }
        } message: { _ in
            Text("Nothing changes until they accept in their app, within 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename, hand over or delete it; you stay in it as a writer.")
        }
        .confirmationDialog("Share “\(members?.vaultName ?? "")” again with the person you verified as “\(resharing.map(Self.verifiedName) ?? "")”?", isPresented: reshareAsked, titleVisibility: .visible, presenting: resharing) { row in
            Button("Share again") {
                act { await model.reshareWithMember(row.userId) }
            }
        } message: { _ in
            Text("They get the vault's key again under the signed kind of sharing, signed by you and sealed to the key you verified for them. Only confirm if you shared this vault with them: the list itself comes from the server.")
        }
    }

    private var members: MembersView? {
        model.state.members.flatMap { $0.vaultId == vaultId ? $0 : nil }
    }

    /// The comparison of codes this screen opened (an invitation's is shown from the vault screen, and one for the people
    /// you verified from theirs).
    private var verifying: Binding<Bool> {
        Binding(
            get: { members != nil && model.state.household == nil && (model.state.verifying.map { !$0.invitation } ?? false) },
            set: { if !$0 { model.cancelVerifying() } }
        )
    }

    private var removeAsked: Binding<Bool> {
        Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })
    }

    private var handOverAsked: Binding<Bool> {
        Binding(get: { handingOver != nil }, set: { if !$0 { handingOver = nil } })
    }

    private var reshareAsked: Binding<Bool> {
        Binding(get: { resharing != nil }, set: { if !$0 { resharing = nil } })
    }

    private static func verifiedName(_ row: LegacyGrantView) -> String {
        row.verifiedLabel ?? row.name
    }

    // MARK: - The list

    private func listSection(_ members: MembersView) -> some View {
        Section {
            if let rows = members.members {
                ForEach(rows, id: \.userId) { member in
                    memberRow(
                        member,
                        managed: members.owner && member.role != "owner" && !member.you,
                        canHandOver: members.canAdd && members.offer == nil && !member.disabled
                    )
                }
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity)
            }
        } header: {
            Text("In “\(members.vaultName)”")
        } footer: {
            Text(
                (members.owner
                    ? "Writers can add and edit items; readers can only view. "
                    : "Only the vault's owner can add, remove or change who has access. ")
                    + "Names and addresses are what the server reports. Verify each person once, by comparing codes with them: andvari never trusts a key just because the server sent it."
            )
        }
        .listRowBackground(Palette.raised)
    }

    private func memberRow(_ member: MemberView, managed: Bool, canHandOver: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(member.you ? "\(member.name) (you)" : member.name)
                        .foregroundStyle(Palette.ink)
                    Text(member.email)
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                }
                Spacer(minLength: 8)
                if managed {
                    Menu {
                        Picker("Role", selection: roleBinding(member)) {
                            Text("Writer: adds and edits items").tag("writer")
                            Text("Reader: only views").tag("reader")
                        }
                        Divider()
                        if canHandOver {
                            Button("Make owner…") {
                                handingOver = member
                            }
                        }
                        Button("Remove from vault…", role: .destructive) {
                            removing = member
                        }
                    } label: {
                        HStack(spacing: 3) {
                            Text(member.role)
                            Image(systemName: "chevron.up.chevron.down")
                                .font(.caption2)
                        }
                        .font(.footnote)
                    }
                    .disabled(model.state.busy)
                    .accessibilityLabel("\(member.name), \(member.role)")
                    .accessibilityHint(canHandOver ? "Change their role, make them the owner, or remove them" : "Change their role, or remove them")
                } else {
                    Text(member.role)
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                }
            }
            if member.disabled {
                Text("The server reports this account as disabled.")
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
            checkLine(member)
        }
        .padding(.vertical, 2)
    }

    /// Kotlin enums arrive as classes with one static member per entry, so they are compared, never switched over.
    @ViewBuilder
    private func checkLine(_ member: MemberView) -> some View {
        if member.check == MemberCheck.verified {
            Label("Verified on this device", systemImage: "checkmark.seal")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
        } else if member.check == MemberCheck.keyChanged {
            VStack(alignment: .leading, spacing: 4) {
                Text("The server now has a different key for them than the one you verified. Check their code again, together, in person. If they did not change devices or reset their account, tell your admin.")
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Verify again…") {
                    open(model.verifyListedMember(member.userId))
                }
                .font(.footnote)
                .buttonStyle(.borderless)
                .disabled(model.state.busy)
            }
        } else if member.check == MemberCheck.notVerified {
            Button("Verify…") {
                open(model.verifyListedMember(member.userId))
            }
            .font(.footnote)
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
        }
    }

    private func roleBinding(_ member: MemberView) -> Binding<String> {
        Binding(
            get: { member.role },
            set: { chosen in
                guard chosen != member.role else { return }
                act { await model.setMemberRole(member.userId, role: chosen) }
            }
        )
    }

    // MARK: - Handing the vault over

    private func offerSection(_ offer: OwnerOfferView, vaultName: String) -> some View {
        Section {
            Text("You asked \(offer.toName) to take over “\(vaultName)”. It's theirs once they accept, which they can do until \(day(offer.expiresAtMs)).")
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            Button("Cancel the offer") {
                act { await model.cancelOwnershipOffer() }
            }
            .disabled(model.state.busy)
        } header: {
            Text("Offer to hand over")
        }
        .listRowBackground(Palette.raised)
    }

    // MARK: - Adding someone

    @ViewBuilder
    private func addSection(_ members: MembersView) -> some View {
        Section {
            TextField("Their email", text: $email)
                .keyboardType(.emailAddress)
                .textContentType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
                .onSubmit(lookUp)
                .onChange(of: email) {
                    // Another address: the person found for the last one is forgotten.
                    if model.state.members?.adding != nil { model.cancelNewMember() }
                }
                .accessibilityIdentifier(AccessID.field("Member email"))
            Button("Look up", action: lookUp)
                .disabled(email.trimmingCharacters(in: .whitespaces).isEmpty || model.state.busy)
            if let adding = members.adding {
                addingRows(adding, vaultName: members.vaultName)
            }
        } header: {
            Text("Add a member")
        } footer: {
            Text("You compare codes with each person once, in person or on a call you trust, not once per vault. The vault's key is sealed to the key you verified, never to one the server sends.")
        }
        .listRowBackground(Palette.raised)
    }

    // MARK: - Sharing again under the signed kind

    private func legacySection(_ members: MembersView) -> some View {
        Section {
            ForEach(members.legacy, id: \.userId) { row in
                legacyRow(row, vaultName: members.vaultName)
            }
        } header: {
            Text("Older kind of sharing")
        } footer: {
            Text("The server lists these members as still on an older kind of sharing that andvari can't check. Share the vault with them again under the signed kind, one person at a time, and only with people you shared it with: the list itself comes from the server.")
        }
        .listRowBackground(Palette.raised)
    }

    /// Kotlin enums arrive as classes with one static member per entry, so they are compared, never switched over.
    @ViewBuilder
    private func legacyRow(_ row: LegacyGrantView, vaultName: String) -> some View {
        if row.check == MemberCheck.verified, let label = row.verifiedLabel {
            VStack(alignment: .leading, spacing: 4) {
                Text("“\(label)”")
                    .foregroundStyle(Palette.ink)
                Text("The name shown when you verified them. The server now calls them \(row.name), \(row.email)." + (row.sharedAtMs.map { " You shared this vault with them on \(day($0.int64Value))." } ?? ""))
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Share again…") {
                    resharing = row
                }
                .font(.footnote)
                .buttonStyle(.borderless)
                .disabled(model.state.busy)
            }
            .padding(.vertical, 2)
        } else if row.check == MemberCheck.keyChanged {
            Text("\(row.name): the server now has a different key for them than the one you verified. Don't share again until you have checked their code together, in person, in the list above.")
                .font(.footnote)
                .foregroundStyle(Palette.danger)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text("Verify \(row.name) (\(row.email)) first, in the list above. Then you can share “\(vaultName)” with them again here.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func addingRows(_ adding: NewMemberView, vaultName: String) -> some View {
        if adding.step == NewMemberStep.verify {
            Text("You haven't verified the person at \(adding.email) on this device yet (the server calls them “\(adding.serverName)”). Do it together, in person or on a call you trust: they read the identity code from their own screen and you type it here, or you scan their QR code.")
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            Button("Verify them…") {
                open(model.verifyNewMember())
            }
            .disabled(model.state.busy)
        } else if adding.step == NewMemberStep.verifyAgain {
            Text(adding.reason ?? "")
                .font(.footnote)
                .foregroundStyle(Palette.danger)
                .fixedSize(horizontal: false, vertical: true)
            Button("Verify them again…") {
                open(model.verifyNewMember())
            }
            .disabled(model.state.busy)
        } else if adding.step == NewMemberStep.ready {
            if let verified = adding.verified {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Verified", systemImage: "checkmark.seal")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(Palette.inkDim)
                    Text("You verified the person at \(verified.email) on \(day(verified.verifiedAtMs)), by their identity code. The name shown when you verified them: “\(verified.label)”.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(IdentityCode.grouped(verified.code))
                        .font(.footnote.monospaced())
                        .foregroundStyle(Palette.inkDim)
                        .accessibilityLabel("Their verified identity code")
                        .accessibilityValue(verified.code.map(String.init).joined(separator: " "))
                }
                Picker("Role", selection: $role) {
                    Text("Writer: adds and edits items").tag("writer")
                    Text("Reader: only views").tag("reader")
                }
                Button("Add \(verified.email) to “\(vaultName)”") {
                    let chosen = role
                    act(then: { email = ""; role = "writer" }) { await model.addNewMember(role: chosen) }
                }
                .disabled(model.state.busy)
            }
        } else if adding.step == NewMemberStep.refused {
            Text(adding.reason ?? "")
                .font(.footnote)
                .foregroundStyle(Palette.danger)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func lookUp() {
        let typed = email
        guard !typed.trimmingCharacters(in: .whitespaces).isEmpty, !model.state.busy else { return }
        act { await model.findNewMember(typed) }
    }

    // MARK: - Helpers

    private func open(_ outcome: Outcome) {
        message = outcome == .ok ? nil : outcome.message
    }

    private func day(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    private func act(then done: @escaping () -> Void = {}, _ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome == .ok { done() } else { message = outcome.message }
        }
    }
}

// MARK: - The people you verified

/// The people this account verified by comparing identity codes with them (root cause A §7.2): the account's own record,
/// the same on all its devices. Someone verified here counts for sharing both ways; taking them off asks for the codes
/// again before anything new is shared with them or accepted from them.
struct VerifiedPeopleView: View {
    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var message: String?
    @State private var email = ""
    @State private var removing: ContactView?

    var body: some View {
        Form {
            if let household = model.state.household {
                if let warning = household.warning {
                    Section {
                        Text(warning)
                            .font(.footnote)
                            .foregroundStyle(Palette.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .listRowBackground(Palette.raised)
                }
                Section {
                    if household.contacts.isEmpty {
                        Text("Nobody yet.")
                            .foregroundStyle(Palette.inkDim)
                    }
                    ForEach(household.contacts, id: \.userId) { contact in
                        contactRow(contact)
                    }
                } header: {
                    Text("People you verified")
                } footer: {
                    Text("Each of you does this once with the other, not once per vault. andvari never trusts a key just because the server sent it.")
                }
                .listRowBackground(Palette.raised)
                Section {
                    TextField("Their email", text: $email)
                        .keyboardType(.emailAddress)
                        .textContentType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.search)
                        .onSubmit(lookUp)
                        .accessibilityIdentifier(AccessID.field("Person email"))
                    Button("Look up and verify", action: lookUp)
                        .disabled(email.trimmingCharacters(in: .whitespaces).isEmpty || model.state.busy)
                } header: {
                    Text("Verify someone")
                } footer: {
                    Text("Do it together, in person or on a call you trust: they read the identity code from their own screen and you type it, or you scan their QR code.")
                }
                .listRowBackground(Palette.raised)
            } else if loading {
                Section {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                .listRowBackground(Color.clear)
            }
            if let message {
                Section {
                    InlineMessage(text: message)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("People you verified")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.openHousehold()
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onDisappear {
            model.closeHousehold()
        }
        .sheet(isPresented: verifying) {
            VerifySheet()
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .confirmationDialog("Remove \(removing.map(Self.who) ?? "")?", isPresented: removeAsked, titleVisibility: .visible, presenting: removing) { contact in
            Button("Remove", role: .destructive) {
                act { await model.removeContact(contact.userId) }
            }
        } message: { _ in
            Text("Vaults already shared with them stay as they are. To share with them again, or to accept a vault from them, compare codes again.")
        }
    }

    private var verifying: Binding<Bool> {
        Binding(
            get: { model.state.household != nil && (model.state.verifying.map { !$0.invitation } ?? false) },
            set: { if !$0 { model.cancelVerifying() } }
        )
    }

    private var removeAsked: Binding<Bool> {
        Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })
    }

    private func contactRow(_ contact: ContactView) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Self.who(contact))
                        .foregroundStyle(Palette.ink)
                    Text("The name shown when you verified them: “\(contact.label)”. \(Self.method(contact.method)), \(day(contact.verifiedAtMs)).")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button("Remove") {
                    removing = contact
                }
                .font(.footnote)
                .buttonStyle(.borderless)
                .disabled(model.state.busy)
            }
            if !contact.confirmedHere {
                Text("Verified on another of your devices. Compare codes again on this one before it counts here.")
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
    }

    private static func who(_ contact: ContactView) -> String {
        contact.email ?? contact.label
    }

    private static func method(_ method: String) -> String {
        switch method {
        case "qr": return "By QR code"
        case "typed": return "By typed code"
        case "enrol": return "At enrolment, in person"
        default: return "Verified"
        }
    }

    private func day(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    private func lookUp() {
        let typed = email
        guard !typed.trimmingCharacters(in: .whitespaces).isEmpty, !model.state.busy else { return }
        act(then: { email = "" }) { await model.findHouseholdMember(typed) }
    }

    private func act(then done: @escaping () -> Void = {}, _ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome == .ok { done() } else { message = outcome.message }
        }
    }
}

// MARK: - Comparing identity codes

/// Comparing identity codes with someone (root cause A §7.2): together, in person or on a call both trust. They read
/// their code from their own screen and it is typed here, or their QR code is scanned. Only a match records them as
/// verified; their code is never shown here first, so nobody can match it by eye against what the server sent.
struct VerifySheet: View {
    @EnvironmentObject private var model: AppModel
    @State private var code = ""
    @State private var message: String?
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Form {
                if let verifying = model.state.verifying {
                    Section {
                        Text(intro(verifying))
                            .font(.subheadline)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .listRowBackground(Palette.raised)

                    Section {
                        if let image = IdentityCode.qrImage(verifying.myQr) {
                            Image(uiImage: image)
                                .interpolation(.none)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 200)
                                .frame(maxWidth: .infinity)
                                .accessibilityLabel("Your identity QR code")
                        }
                        Text(IdentityCode.grouped(verifying.myCode))
                            .font(.body.monospaced())
                            .foregroundStyle(Palette.ink)
                            .frame(maxWidth: .infinity)
                            .accessibilityLabel("Your identity code")
                            .accessibilityValue(verifying.myCode.map(String.init).joined(separator: " "))
                    } header: {
                        Text("Your code")
                    } footer: {
                        Text("Show them this: they type your code on their device, or scan the QR code.")
                    }
                    .listRowBackground(Palette.raised)

                    Section {
                        TextField("From their screen, not this one", text: $code)
                            .font(.body.monospaced())
                            .keyboardType(.asciiCapable)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .submitLabel(.done)
                            .onSubmit(checkCode)
                            .accessibilityIdentifier(AccessID.field("Their code"))
                        Button("Verify", action: checkCode)
                            .disabled(IdentityCode.hexCount(code) != 32 || model.state.busy)
                        if QrScanning.supported {
                            Button("Scan their QR code instead") {
                                message = nil
                                scanning = true
                            }
                            .disabled(model.state.busy)
                        }
                    } header: {
                        Text("\(verifying.serverName)'s code")
                    } footer: {
                        Text("Type the 32 characters as they read them from their own screen. Spaces and capitals don't matter.")
                    }
                    .listRowBackground(Palette.raised)

                    if let message {
                        Section {
                            InlineMessage(text: message)
                        }
                        .listRowBackground(Color.clear)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle("Compare codes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        model.cancelVerifying()
                    }
                }
            }
            .sheet(isPresented: $scanning) {
                QrScannerSheet(
                    found: { payload in
                        scanning = false
                        checkQr(payload)
                    },
                    cancel: { scanning = false }
                )
                .interactiveDismissDisabled()
                .privacyShield()
            }
        }
        .interactiveDismissDisabled(model.state.busy)
        .onDisappear {
            code = ""
        }
    }

    private func intro(_ verifying: VerifyView) -> String {
        if verifying.invitation {
            return "\(verifying.serverName) (as the server names them) wants to share a vault with you. Compare codes together, in person or on a call you trust: show them your code, and they show you theirs. The vault opens once their code matches."
        }
        let whom = verifying.email.map { "\(verifying.serverName), at \($0)" } ?? verifying.serverName
        return "Verifying \(whom). Do this together, in person or on a call you trust: show them your code, and they show you theirs."
    }

    private func checkCode() {
        let typed = code
        guard IdentityCode.hexCount(typed) == 32, !model.state.busy else { return }
        message = nil
        Task {
            let outcome = await model.verifyWithCode(typed)
            if outcome != .ok { message = outcome.message }
        }
    }

    private func checkQr(_ payload: String) {
        message = nil
        Task {
            let outcome = await model.verifyWithQr(payload)
            if outcome != .ok { message = outcome.message }
        }
    }
}

// MARK: - Identity codes and QR codes

enum IdentityCode {
    /// A 32-hex code in groups of four, on two lines, for reading aloud.
    static func grouped(_ hex: String) -> String {
        let groups = stride(from: 0, to: hex.count, by: 4).map { start -> String in
            let from = hex.index(hex.startIndex, offsetBy: start)
            let to = hex.index(from, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[from..<to])
        }
        let half = (groups.count + 1) / 2
        return groups.prefix(half).joined(separator: " ") + "\n" + groups.dropFirst(half).joined(separator: " ")
    }

    /// The hex digits in what was typed (the core ignores everything else).
    static func hexCount(_ typed: String) -> Int {
        typed.lowercased().filter { "0123456789abcdef".contains($0) }.count
    }

    /// A QR code image of [text], drawn on this device.
    static func qrImage(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

// MARK: - Scanning a QR code

@MainActor
enum QrScanning {
    /// The camera scanner exists on this device (VisionKit's data scanner).
    static var supported: Bool {
        DataScannerViewController.isSupported
    }
}

/// The camera, reading one QR code. Camera access is asked for here, the first time; without it, typing the code is
/// the way. Nothing is kept: the scanner hands over the text of the first QR code it reads, and stops.
struct QrScannerSheet: View {
    let found: (String) -> Void
    let cancel: () -> Void

    @State private var access = AVCaptureDevice.authorizationStatus(for: .video)

    var body: some View {
        NavigationStack {
            Group {
                switch access {
                case .authorized:
                    if DataScannerViewController.isAvailable {
                        QrDataScanner(found: found)
                            .ignoresSafeArea(edges: .bottom)
                    } else {
                        unavailable("The camera can't scan right now. Type their code instead.")
                    }
                case .notDetermined:
                    ProgressView()
                        .task {
                            let granted = await AVCaptureDevice.requestAccess(for: .video)
                            access = granted ? .authorized : .denied
                        }
                default:
                    unavailable("andvari isn't allowed to use the camera. Type their code instead, or allow the camera for andvari in the Settings app.")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Palette.background)
            .navigationTitle("Scan their QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: cancel)
                }
            }
        }
    }

    private func unavailable(_ text: String) -> some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(Palette.inkDim)
            .multilineTextAlignment(.center)
            .padding(24)
    }
}

/// VisionKit's data scanner, set to QR codes only.
struct QrDataScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(found: found)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        if !scanner.isScanning, !context.coordinator.done {
            try? scanner.startScanning()
        }
    }

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        private(set) var done = false

        init(found: @escaping (String) -> Void) {
            self.found = found
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for item in addedItems {
                if case let .barcode(barcode) = item, let payload = barcode.payloadStringValue {
                    done = true
                    dataScanner.stopScanning()
                    found(payload)
                    return
                }
            }
        }
    }
}

// MARK: - Invitations

/// A shared vault someone wants to share with this account, from someone this device has not verified (root cause A
/// §1.6). It stays closed, and its name unshown, until the person compares codes with the sender.
struct InvitationRow: View {
    let invitation: InvitationView

    @EnvironmentObject private var model: AppModel
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(sender) wants to share a vault with you.")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.ink)
                .fixedSize(horizontal: false, vertical: true)
            Text("Verify them to accept: compare identity codes, in person or on a call you trust. Until then the vault stays closed.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 20) {
                Button("Verify and accept") {
                    message = nil
                    Task {
                        let outcome = await model.verifyInvitation(invitation.id)
                        if outcome != .ok { message = outcome.message }
                    }
                }
                .font(.subheadline.weight(.semibold))
                Button("Decline") {
                    model.declineInvitation(invitation.id)
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
            if let message {
                InlineMessage(text: message)
            }
        }
        .padding(.vertical, 4)
    }

    private var sender: String {
        invitation.from.map { "\($0) (as the server names them)" } ?? "Someone"
    }
}

// MARK: - Shared vaults awaiting review

/// A shared vault this account reads only through an older kind of sharing andvari can't check (root cause A §8.2): it
/// can't confirm who sent it, so nothing is saved into it until the person accepts it (trust on first use) or leaves it.
struct LegacyReviewRow: View {
    let review: LegacyReviewView

    @EnvironmentObject private var model: AppModel
    @State private var message: String?
    @State private var leaving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("“\(name)”")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.ink)
            Text("Not yet verified · \(items) · \(owner)")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 20) {
                Button("Accept") {
                    run { await model.acceptLegacyVault(review.vaultId) }
                }
                .font(.subheadline.weight(.semibold))
                Button("Leave…", role: .destructive) {
                    leaving = true
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
            if let message {
                InlineMessage(text: message)
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog("Leave “\(name)”?", isPresented: $leaving, titleVisibility: .visible) {
            Button("Leave vault", role: .destructive) {
                run { await model.leaveSharedVault(review.vaultId) }
            }
        } message: {
            Text("You'll lose access on all your devices. The items stay with the owner and other members; only the owner can add you back.")
        }
    }

    private var name: String {
        review.name ?? "Unnamed vault"
    }

    private var items: String {
        review.itemCount == 1 ? "1 item" : "\(review.itemCount) items"
    }

    private var owner: String {
        review.owner.map { "owner \($0), as the server names them" } ?? "owner not known yet"
    }

    private func run(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}

// MARK: - Ownership on record

/// "You own <vault>?" (A6b): the server lists this account as the vault's owner, but the account's own record doesn't say
/// so, and the server's word alone never lets this device add anyone or sign anything for the vault. What the server
/// reports is shown first; the master password, checked on this device, confirms it. Rows for a Form section.
struct OwnershipConfirmRows: View {
    let vaultId: String
    let vaultName: String

    @EnvironmentObject private var model: AppModel
    @State private var password = ""
    @State private var handedOver = false
    @State private var message: String?

    var body: some View {
        if let claim = model.state.ownershipClaim, claim.vaultId == vaultId {
            Text("Only confirm if you created “\(claim.vaultName)”, or its owner handed it over to you.")
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(claim.lines, id: \.self) { line in
                Text(line)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if claim.receivedAsMember {
                Toggle(isOn: $handedOver) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Its owner handed this vault over to me")
                            .font(.footnote)
                        Text("This device first got this vault as a member.")
                            .font(.caption)
                            .foregroundStyle(Palette.inkDim)
                    }
                }
            }
            SecureField("Master password (required)", text: $password)
                .textContentType(.password)
                .font(.subheadline)
            HStack(spacing: 20) {
                Button("Confirm") {
                    confirm(claim)
                }
                .font(.subheadline.weight(.semibold))
                .disabled(model.state.busy || password.isEmpty || (claim.receivedAsMember && !handedOver))
                Button("Cancel") {
                    password = ""
                    handedOver = false
                    message = nil
                    model.cancelOwnershipClaim()
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
        } else {
            Text("The server reports you as this vault's owner, but this account has no record that you created it or that its owner handed it over to you. Confirm it only if one of those is true; otherwise, tell your admin.")
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            Button("Confirm I own “\(vaultName)”…") {
                message = nil
                Task {
                    let outcome = await model.describeOwnership(vaultId)
                    if outcome != .ok { message = outcome.message }
                }
            }
            .disabled(model.state.busy)
        }
        if let message {
            InlineMessage(text: message)
        }
    }

    private func confirm(_ claim: OwnershipClaimView) {
        let typed = password
        let handed = claim.receivedAsMember && handedOver
        password = ""
        message = nil
        Task {
            let outcome = await model.confirmOwnership(password: typed, handedOver: handed)
            if outcome == .ok { handedOver = false } else { message = outcome.message }
        }
    }
}

// MARK: - Offers to take a vault over

/// An offer to make this account the owner of a shared vault (spec 03 §11). It is shown only once it verified under the
/// vault's own key, so the server cannot make one up; who sent it is the server's word, to confirm with them.
struct OwnershipOfferRow: View {
    let offer: OwnershipOfferView

    @EnvironmentObject private var model: AppModel
    @State private var message: String?
    @State private var confirming = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(owner) wants to make you the owner of “\(offer.vaultName)”.")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.ink)
                .fixedSize(horizontal: false, vertical: true)
            Text("The offer was signed with the vault's own key. To be sure it came from them, and not from a server that was broken into, ask them in person or on a call you trust. As its owner you would manage its members, and only you could rename, hand over or delete it.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 20) {
                Button("Become the owner") {
                    confirming = true
                }
                .font(.subheadline.weight(.semibold))
                Button("Decline") {
                    run { await model.declineOwnership(offer.vaultId) }
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
            if let message {
                InlineMessage(text: message)
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog("Become the owner of “\(offer.vaultName)”?", isPresented: $confirming, titleVisibility: .visible) {
            Button("Become the owner") {
                run { await model.acceptOwnership(offer.vaultId) }
            }
        } message: {
            Text("\(owner) stays in the vault as a writer.")
        }
    }

    private var owner: String {
        offer.from.map { "\($0) (as the server names them)" } ?? "The vault's owner"
    }

    private func run(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}
