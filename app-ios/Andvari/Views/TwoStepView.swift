import AndvariCore
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

/// Two-step sign-in: an extra one-time code the server checks at every sign-in, from an authenticator. Separate from
/// the vault's encryption. Turning it on takes the master password; turning it off takes a current code.
struct TwoStepView: View {
    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var password = ""
    @State private var code = ""
    @State private var message: String?
    @State private var working = false
    @State private var copiedSecret = false

    var body: some View {
        Form {
            Section {
                Text("An extra one-time code checked at every sign-in, from an authenticator app. It is separate from your vault's encryption.")
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .listRowBackground(Color.clear)

            if let status = model.state.twoStep {
                if status.settingUp, let setup = model.twoStepSetup() {
                    setupSections(setup)
                } else if status.enrolled {
                    Section {
                        LabeledContent("Two-step sign-in", value: "On")
                    }
                    .listRowBackground(Palette.raised)
                    Section {
                        codeField
                        Button("Turn off", role: .destructive) {
                            act { await model.disableTwoStep(code: code.trimmed) }
                        }
                        .disabled(code.trimmed.count < 6 || working)
                    } header: {
                        Text("Turn off")
                    } footer: {
                        Text("Enter a current code from your authenticator.")
                    }
                    .listRowBackground(Palette.raised)
                } else {
                    Section {
                        LabeledContent("Two-step sign-in", value: "Off")
                    }
                    .listRowBackground(Palette.raised)
                    Section {
                        SecureField("Master password", text: $password)
                            .textContentType(.password)
                        Button("Turn on") {
                            let typed = password
                            password = ""
                            act { await model.beginTwoStep(password: typed) }
                        }
                        .disabled(password.isEmpty || working)
                    } header: {
                        Text("Turn on")
                    } footer: {
                        Text("Your master password proves it is you before a new code is set up.")
                    }
                    .listRowBackground(Palette.raised)
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
        .navigationTitle("Two-step sign-in")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.loadTwoStep()
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onDisappear {
            password = ""
            code = ""
            model.closeTwoStep()
        }
    }

    @ViewBuilder
    private func setupSections(_ setup: TwoStepSetup) -> some View {
        Section {
            if let qr = Self.qrImage(setup.uri) {
                Image(uiImage: qr)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 220)
                    .frame(maxWidth: .infinity)
                    .accessibilityLabel("QR code for your authenticator")
            }
            // The setup key, grouped for typing into an authenticator by hand. Not selectable: Copy keeps it on this
            // device and lets it expire.
            Text(Self.grouped(setup.secret))
                .font(.body.monospaced())
                .foregroundStyle(Palette.ink)
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 20) {
                Button(copiedSecret ? "Copied" : "Copy key") {
                    Clipboard.copy(setup.secret)
                    copiedSecret = true
                }
                if let url = URL(string: setup.uri) {
                    Link("Open in authenticator", destination: url)
                }
            }
            .buttonStyle(.borderless)
            .font(.subheadline)
        } header: {
            Text("Add to your authenticator")
        } footer: {
            Text("Scan the code with an authenticator app on another device, or add the key by hand.")
        }
        .listRowBackground(Palette.raised)
        Section {
            codeField
            Button("Confirm") {
                act { await model.confirmTwoStep(code: code.trimmed) }
            }
            .disabled(code.trimmed.count < 6 || working)
        } header: {
            Text("Confirm")
        } footer: {
            Text("Enter the code your authenticator shows now. Two-step sign-in is on once it is confirmed.")
        }
        .listRowBackground(Palette.raised)
    }

    private var codeField: some View {
        TextField("6-digit code", text: $code)
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
            .font(.body.monospaced())
            .autocorrectionDisabled()
    }

    private func act(_ action: @escaping () async -> Outcome) {
        working = true
        message = nil
        Task {
            let outcome = await action()
            working = false
            code = ""
            if outcome != .ok { message = outcome.message }
        }
    }

    /// Base32 in groups of four, so it can be typed into an authenticator.
    private static func grouped(_ secret: String) -> String {
        stride(from: 0, to: secret.count, by: 4).map { start in
            let from = secret.index(secret.startIndex, offsetBy: start)
            let to = secret.index(from, offsetBy: 4, limitedBy: secret.endIndex) ?? secret.endIndex
            return String(secret[from..<to])
        }
        .joined(separator: " ")
    }

    private static func qrImage(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
