import AndvariCore
import SwiftUI
import UniformTypeIdentifiers

/// Importing a CSV export from another password manager or a browser (spec 06; the Android app's flow on core's
/// universal importer). The file is read and planned on this iPhone: what it would add, against what the vault already
/// holds, is shown before anything is sent, and each item is encrypted here like any other save.
struct ImportView: View {
    /// core's CsvImport.MAX_BYTES: a bigger file is refused, never read whole.
    private static let maxBytes = 10 * 1024 * 1024

    @EnvironmentObject private var model: AppModel
    @Environment(\.isPresented) private var isPresented
    @State private var choosing = false
    @State private var message: String?

    var body: some View {
        Form {
            if let plan = model.state.csvImport {
                preview(plan)
            } else {
                start
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
        .navigationTitle("Import passwords")
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.commaSeparatedText, .plainText], allowsMultipleSelection: false) { result in
            read(result)
        }
        .onDisappear {
            // The parsed file is plaintext: it goes with the screen.
            if !isPresented { model.closeImport() }
        }
    }

    // MARK: - Before a file

    @ViewBuilder
    private var start: some View {
        Section {
            Text("Import the passwords you exported from another password manager or a browser, as a CSV file. andvari reads exports from Chrome and other Chromium browsers, Firefox, Safari, Bitwarden, 1Password 8 or newer, and LastPass.")
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
            Button("Choose a CSV file…") {
                message = nil
                choosing = true
            }
            .disabled(model.state.busy)
        } footer: {
            Text("The file is read on this iPhone. You see what it would add before anything is imported.")
        }
        .listRowBackground(Palette.raised)
        Section {
            ForEach(ImportHelp.shared.SOURCES, id: \.label) { source in
                DisclosureGroup(source.label) {
                    ForEach(Array(source.steps.enumerated()), id: \.offset) { index, step in
                        Text("\(index + 1). \(step)")
                            .font(.footnote)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let note = source.note {
                        Text(note)
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } header: {
            Text("How to export")
        }
        .listRowBackground(Palette.raised)
    }

    // MARK: - What the file holds

    @ViewBuilder
    private func preview(_ plan: CsvImportView) -> some View {
        Section {
            Text("This file holds every password in plain text. Nothing is sent as it is: each item is encrypted on this iPhone before it goes to your server. When you're done, delete the file.")
                .font(.footnote)
                .foregroundStyle(Palette.danger)
                .fixedSize(horizontal: false, vertical: true)
            LabeledContent("Exported from", value: plan.source)
            if let note = plan.note {
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .listRowBackground(Palette.raised)
        Section {
            if plan.vaultChoices.isEmpty {
                LabeledContent("Import into", value: plan.vaultName)
            } else {
                Picker("Import into", selection: vaultBinding(plan)) {
                    ForEach(plan.vaultChoices, id: \.vaultId) { vault in
                        Text(vault.personal ? "\(vault.name) (personal)" : vault.name).tag(vault.vaultId)
                    }
                }
                .disabled(plan.busy)
            }
        } footer: {
            if !plan.vaultChoices.isEmpty {
                Text("Everyone in a shared vault sees what is imported into it. Choosing another vault checks the file against what that vault holds.")
            }
        }
        .listRowBackground(Palette.raised)
        Section {
            Text(plan.toImport == 1 ? "1 item to import" : "\(plan.toImport) items to import")
                .font(.subheadline.weight(.semibold))
            ForEach(plan.counts, id: \.self) { line in
                Text(line)
                    .font(.footnote)
            }
            ForEach(plan.buckets, id: \.title) { bucket in
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
            ForEach(plan.errors, id: \.self) { line in
                Text(line)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            Text("What the file holds")
        }
        .listRowBackground(Palette.raised)
        Section {
            if let progress = plan.progress {
                ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1))) {
                    Text("Importing… \(progress.done) of \(progress.total)")
                        .font(.footnote)
                }
            }
            if let error = plan.error {
                InlineMessage(text: error)
            }
            if let done = plan.done {
                Text(done)
                    .font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Done") {
                    model.closeImport()
                }
            } else if plan.error != nil && !plan.retryable {
                Button("OK") {
                    model.closeImport()
                }
            } else {
                let title = plan.error != nil ? "Retry" : (plan.toImport == 1 ? "Import 1 item" : "Import \(plan.toImport) items")
                Button(title) {
                    act { await model.confirmImport() }
                }
                .disabled(plan.busy || plan.toImport == 0 || model.state.busy)
                Button("Cancel", role: .cancel) {
                    model.closeImport()
                }
                .disabled(plan.busy)
            }
        }
        .listRowBackground(Palette.raised)
    }

    private func vaultBinding(_ plan: CsvImportView) -> Binding<String> {
        Binding(
            get: { plan.vaultId },
            set: { chosen in
                guard chosen != plan.vaultId else { return }
                act { await model.setImportVault(chosen) }
            }
        )
    }

    // MARK: - Reading the file

    private func read(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped { url.stopAccessingSecurityScopedResource() }
        }
        let data: Data
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            // One byte past the limit is enough to know the file is too big: it is never read whole.
            data = try handle.read(upToCount: Self.maxBytes + 1) ?? Data()
        } catch {
            message = "That file couldn't be read. Choose it again."
            return
        }
        guard data.count <= Self.maxBytes else {
            message = "That file is larger than 10 MiB, far bigger than any real password export."
            return
        }
        // Core zeroes its copy of the bytes once they are parsed; this one goes when the call returns.
        act { await model.importCsv(data) }
    }

    private func act(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}
