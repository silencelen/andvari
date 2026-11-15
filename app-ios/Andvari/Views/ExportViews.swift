import AndvariCore
import Foundation
import SwiftUI
import UniformTypeIdentifiers

/// Backing up the vault, and exporting it for another password manager (spec 07; the Android and desktop apps' flows on
/// core's Export). The file is made in memory once a folder is chosen, written into that folder once, then read back and
/// compared. Nothing is written anywhere else, so no copy of a plaintext CSV outlives the export.
struct ExportOptionsView: View {
    var body: some View {
        Form {
            Section {
                NavigationLink {
                    ExportScreen(kind: ExportKind.backup)
                } label: {
                    Label("Back up…", systemImage: "lock.doc")
                }
                NavigationLink {
                    ExportScreen(kind: ExportKind.csv)
                } label: {
                    Label("Export for another password manager…", systemImage: "tablecells")
                }
            } footer: {
                Text("A backup keeps everything, encrypted under a passphrase you set. A CSV holds your logins in plain text, to import into another app.")
            }
            .listRowBackground(Palette.raised)
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("Back up and export")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ExportScreen: View {
    let kind: ExportKind

    @EnvironmentObject private var model: AppModel
    @Environment(\.isPresented) private var isPresented
    @State private var loading = true
    @State private var message: String?
    @State private var acknowledged = false
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var choosing = false

    private var export: ExportView? {
        model.state.export.flatMap { $0.kind == kind ? $0 : nil }
    }

    var body: some View {
        Form {
            if let export {
                content(export)
            } else if loading {
                ProgressView()
                    .frame(maxWidth: .infinity)
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
        .navigationTitle(kind == ExportKind.backup ? "Back up" : "Export as CSV")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.openExport(kind)
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onChange(of: export?.formulaCells ?? []) {
            // Another list of cells needs a tick of its own.
            acknowledged = false
        }
        .onDisappear {
            if !isPresented {
                passphrase = ""
                confirm = ""
                model.closeExport()
            }
        }
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.folder], allowsMultipleSelection: false) { result in
            save(result)
        }
    }

    // MARK: - What the export holds

    @ViewBuilder
    private func content(_ export: ExportView) -> some View {
        Section {
            if let note = export.offlineNote {
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if kind == ExportKind.csv {
                Text(ExportCopy.shared.CSV_PLAINTEXT)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(ExportCopy.shared.BACKUP_ABOUT)
                    .font(.footnote)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if export.vaults.count > 1 {
                Text(ExportCopy.shared.PRIVATE)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .listRowBackground(Palette.raised)
        Section {
            ForEach(export.vaults, id: \.vaultId) { vault in
                if vault.personal {
                    LabeledContent(vault.name, value: "Always included")
                } else {
                    Toggle(isOn: vaultBinding(vault)) {
                        Text("\(vault.name) (shared)")
                    }
                    .disabled(export.busy)
                }
            }
        } header: {
            Text("Vaults")
        }
        .listRowBackground(Palette.raised)
        if kind == ExportKind.csv {
            csvSections(export)
        } else {
            backupSections(export)
        }
        Section {
            if let error = export.error {
                InlineMessage(text: error)
            }
            if let done = export.done {
                Text(done)
                    .font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if export.busy {
                ProgressView(kind == ExportKind.backup ? "Making the backup…" : "Making the file…")
            }
            Button("Choose a folder…") {
                message = nil
                choosing = true
            }
            .disabled(!ready(export))
        } footer: {
            Text("The file is written into the folder you choose, and read back to check it. Nothing is kept anywhere else.")
        }
        .listRowBackground(Palette.raised)
    }

    @ViewBuilder
    private func csvSections(_ export: ExportView) -> some View {
        Section {
            Text(export.count == 1 ? "1 login is written." : "\(export.count) logins are written.")
                .font(.subheadline.weight(.semibold))
            ForEach(export.warnings, id: \.title) { bucket in
                DisclosureGroup {
                    ForEach(bucket.names, id: \.self) { name in
                        Text(name)
                            .font(.footnote)
                    }
                    if Int(bucket.count) > bucket.names.count {
                        Text("And \(Int(bucket.count) - bucket.names.count) more.")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                    }
                } label: {
                    Text("\(bucket.title): \(bucket.count)")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } header: {
            Text("What the file holds")
        }
        .listRowBackground(Palette.raised)
        if !export.formulaCells.isEmpty {
            Section {
                Text(ExportCopy.shared.FORMULA_WARNING)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(export.formulaCells, id: \.self) { cell in
                    Text(cell)
                        .font(.footnote)
                }
                Toggle(isOn: $acknowledged) {
                    Text(ExportCopy.shared.FORMULA_ACK)
                        .font(.footnote)
                }
            }
            .listRowBackground(Palette.raised)
        }
    }

    @ViewBuilder
    private func backupSections(_ export: ExportView) -> some View {
        Section {
            Text(export.count == 1 ? "1 item is backed up." : "\(export.count) items are backed up.")
                .font(.subheadline.weight(.semibold))
            Toggle(isOn: attachmentsBinding(export)) {
                Text("Include attached files (\(ByteCountFormatter.string(fromByteCount: export.attachmentBytes, countStyle: .file)))")
            }
            .disabled(export.busy)
            if !export.attachmentsLeftOut.isEmpty {
                Text("Left out, over the 64 MiB total: " + export.attachmentsLeftOut.map { "“\($0)”" }.joined(separator: ", "))
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .listRowBackground(Palette.raised)
        Section {
            SecureField("Backup passphrase", text: $passphrase)
                .textContentType(.newPassword)
                .accessibilityIdentifier(AccessID.field("Backup passphrase"))
            SecureField("Confirm passphrase", text: $confirm)
                .textContentType(.newPassword)
                .accessibilityIdentifier(AccessID.field("Backup passphrase again"))
            if !passphrase.isEmpty {
                let score = Strength.shared.estimateStrength(pw: passphrase)
                let enough = score >= Strength.shared.BACKUP_FLOOR
                Text("Strength: \(Strength.shared.label(score: score))" + (enough ? "" : ", needs at least “good”"))
                    .font(.footnote)
                    .foregroundStyle(enough ? Palette.inkDim : Palette.danger)
                if let pattern = Strength.shared.patternWarning(pw: passphrase) {
                    Text(pattern)
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if !confirm.isEmpty && confirm != passphrase {
                Text(ExportCopy.shared.PASSPHRASES_DIFFER)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
            if passphrase.unicodeScalars.contains(where: { $0.value > 127 }) {
                Text(ExportCopy.shared.NON_ASCII)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            Text("Passphrase")
        } footer: {
            Text(ExportCopy.shared.PASSPHRASE_TIP)
        }
        .listRowBackground(Palette.raised)
    }

    private func ready(_ export: ExportView) -> Bool {
        if export.busy || model.state.busy { return false }
        if kind == ExportKind.csv { return export.count > 0 && (export.formulaCells.isEmpty || acknowledged) }
        return !passphrase.isEmpty && passphrase == confirm
    }

    private func vaultBinding(_ vault: ExportVaultView) -> Binding<Bool> {
        Binding(
            get: { vault.included },
            set: { model.setExportVault(vault.vaultId, included: $0) }
        )
    }

    private func attachmentsBinding(_ export: ExportView) -> Binding<Bool> {
        Binding(
            get: { export.includeAttachments },
            set: { model.setExportAttachments($0) }
        )
    }

    // MARK: - Writing into the folder chosen

    private func save(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let folder = urls.first else { return }
        let phrase = passphrase
        let again = confirm
        Task {
            let made: ExportData?
            if kind == ExportKind.csv {
                made = model.exportCsv(acknowledged: acknowledged)
            } else {
                made = await model.exportBackup(passphrase: phrase, confirm: again)
            }
            // Nil: nothing was made, and the export screen says why.
            guard let made else { return }
            defer { made.data.resetBytes(in: NSRange(location: 0, length: made.data.length)) }
            do {
                let name = try ExportFolder.write(made.data, named: made.fileName, into: folder)
                model.exportSaved(fileName: name, folder: folder.lastPathComponent)
                if kind == ExportKind.backup {
                    passphrase = ""
                    confirm = ""
                }
            } catch ExportFolder.Failure.readBack {
                model.exportNotSaved(written: true)
            } catch {
                model.exportNotSaved(written: false)
            }
        }
    }
}

/// Writes an export into the folder the person chose, once, under a name not already taken there, and reads it back
/// (spec 07 §2.6): a file that does not read back as written is removed again. Nothing is written anywhere else.
enum ExportFolder {
    enum Failure: Error {
        case write
        case readBack
    }

    static func write(_ data: NSMutableData, named fileName: String, into folder: URL) throws -> String {
        let scoped = folder.startAccessingSecurityScopedResource()
        defer {
            if scoped { folder.stopAccessingSecurityScopedResource() }
        }
        let target = freeName(fileName, in: folder)
        let coordinator = NSFileCoordinator()
        var coordination: NSError?
        var written = false
        coordinator.coordinate(writingItemAt: target, options: [], error: &coordination) { url in
            written = (try? data.write(to: url, options: [.withoutOverwriting])) != nil
        }
        guard coordination == nil, written else { throw Failure.write }
        var same = false
        coordinator.coordinate(readingItemAt: target, options: [.withoutChanges], error: &coordination) { url in
            guard let back = NSMutableData(contentsOf: url) else { return }
            same = back.isEqual(data)
            back.resetBytes(in: NSRange(location: 0, length: back.length))
        }
        guard same else {
            var removal: NSError?
            coordinator.coordinate(writingItemAt: target, options: [.forDeleting], error: &removal) { url in
                try? FileManager.default.removeItem(at: url)
            }
            throw Failure.readBack
        }
        return target.lastPathComponent
    }

    /// [fileName] in [folder], or "name (2).ext" and on while that is taken: an export never replaces a file.
    private static func freeName(_ fileName: String, in folder: URL) -> URL {
        let base = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension
        var candidate = folder.appendingPathComponent(fileName)
        var n = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = folder.appendingPathComponent("\(base) (\(n)).\(ext)")
            n += 1
        }
        return candidate
    }
}
