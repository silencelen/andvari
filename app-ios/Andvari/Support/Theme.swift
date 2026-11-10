import SwiftUI
import UIKit

// MARK: - Palette

/// The andvari treasury palette (extension/popup.css): near-black and gold, with its light variant.
/// Every colour follows the system appearance.
enum Palette {
    static let background = dynamic(light: 0xF4EFE4, dark: 0x14120E)
    static let raised = dynamic(light: 0xFBF8F1, dark: 0x1E1B15)
    static let input = dynamic(light: 0xFFFFFF, dark: 0x262119)
    static let edge = dynamic(light: 0xE0D8C5, dark: 0x38311F)
    static let edgeStrong = dynamic(light: 0xC9BFA2, dark: 0x4A3F28)
    static let ink = dynamic(light: 0x2C2517, dark: 0xEDE4D0)
    static let inkDim = dynamic(light: 0x6B6047, dark: 0xA79C85)
    static let inkFaint = dynamic(light: 0x786C50, dark: 0x8D8370)
    static let gold = dynamic(light: 0x9A7420, dark: 0xD0A94A)
    static let goldBright = dynamic(light: 0x7D5E14, dark: 0xE8C66A)
    static let goldText = dynamic(light: 0x7D5E14, dark: 0xD0A94A)
    static let goldHigh = dynamic(light: 0x8F6B16, dark: 0xE8C66A)
    static let goldLow = dynamic(light: 0x7D5E14, dark: 0xD0A94A)
    static let buttonInk = dynamic(light: 0xFDF9F0, dark: 0x1A1509)
    static let glyphHigh = dynamic(light: 0xE9D9A6, dark: 0x8A6D28)
    static let glyphLow = dynamic(light: 0xD8BD7A, dark: 0x2A2110)
    static let danger = dynamic(light: 0xB3402C, dark: 0xD97F6F)
    static let ok = dynamic(light: 0x4F7A3A, dark: 0x7FA86A)

    private static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            rgb(traits.userInterfaceStyle == .dark ? dark : light)
        })
    }

    private static func rgb(_ hex: UInt32) -> UIColor {
        UIColor(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }
}

/// The page behind the sign-in screens: the palette's background with a faint warm light from above.
struct TreasuryBackground: View {
    var body: some View {
        ZStack {
            Palette.background
            RadialGradient(
                colors: [Palette.gold.opacity(0.10), Color.clear],
                center: UnitPoint(x: 0.5, y: -0.1),
                startRadius: 0,
                endRadius: 560
            )
        }
        .ignoresSafeArea()
    }
}

// MARK: - The mark

/// The andvari sigil: a stave and a crossing stroke, on the web Sigil's 24-point grid.
struct SigilShape: Shape {
    func path(in rect: CGRect) -> Path {
        let unit = min(rect.width, rect.height) / 24
        let originX = rect.midX - 12 * unit
        let originY = rect.midY - 12 * unit
        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: originX + x * unit, y: originY + y * unit)
        }
        var path = Path()
        path.move(to: point(12, 3))
        path.addLine(to: point(12, 21))
        path.move(to: point(5.5, 8.5))
        path.addLine(to: point(18.5, 14.5))
        return path
    }
}

struct Sigil: View {
    var size: CGFloat = 44

    var body: some View {
        SigilShape()
            .stroke(Palette.gold, style: StrokeStyle(lineWidth: size * 1.8 / 24, lineCap: .round))
            .frame(width: size, height: size)
            .shadow(color: Palette.gold.opacity(0.35), radius: size / 4)
            .accessibilityHidden(true)
    }
}

struct Wordmark: View {
    var body: some View {
        HStack(spacing: 0) {
            Text("and").foregroundStyle(Palette.gold)
            Text("vari").foregroundStyle(Palette.ink)
        }
        .font(.system(.title, design: .serif).weight(.semibold))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("andvari")
        .accessibilityAddTraits(.isHeader)
    }
}

/// The sigil over the wordmark, at the top of the sign-in screens.
struct Brand: View {
    var body: some View {
        VStack(spacing: 12) {
            Sigil(size: 52)
            Wordmark()
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 28)
        .padding(.bottom, 4)
    }
}

/// An item's tile: its initial on a gold-lit plate, or a symbol for notes and cards.
struct ItemGlyph: View {
    let name: String
    let type: String
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 34

    init(name: String, type: String) {
        self.name = name
        self.type = type
    }

    var body: some View {
        let plate = RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
        ZStack {
            plate.fill(
                RadialGradient(
                    colors: [Palette.glyphHigh, Palette.glyphLow],
                    center: UnitPoint(x: 0.3, y: 0.3),
                    startRadius: 0,
                    endRadius: size
                )
            )
            plate.strokeBorder(Palette.edgeStrong, lineWidth: 1)
            mark.foregroundStyle(Palette.goldBright)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    @ViewBuilder private var mark: some View {
        switch type {
        case "note":
            Image(systemName: "note.text").font(.system(size: size * 0.42, weight: .semibold))
        case "card":
            Image(systemName: "creditcard").font(.system(size: size * 0.4, weight: .semibold))
        default:
            Text(initial).font(.system(size: size * 0.46, weight: .semibold, design: .serif))
        }
    }

    private var initial: String {
        guard let first = name.trimmed.first else { return "·" }
        return String(first).uppercased()
    }
}

// MARK: - Buttons

/// The gold action button.
struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        PrimaryBody(configuration: configuration)
    }

    private struct PrimaryBody: View {
        let configuration: ButtonStyleConfiguration
        @Environment(\.isEnabled) var isEnabled

        var body: some View {
            configuration.label
                .font(.body.weight(.semibold))
                .foregroundStyle(Palette.buttonInk)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
                .background(
                    LinearGradient(colors: [Palette.goldHigh, Palette.goldLow], startPoint: .top, endPoint: .bottom),
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                )
                .opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1) : 0.5)
                .saturation(isEnabled ? 1 : 0.4)
        }
    }
}

/// The plain bordered button beside or below a gold one.
struct QuietButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        QuietBody(configuration: configuration)
    }

    private struct QuietBody: View {
        let configuration: ButtonStyleConfiguration
        @Environment(\.isEnabled) var isEnabled

        var body: some View {
            configuration.label
                .font(.body)
                .foregroundStyle(Palette.ink)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Palette.raised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Palette.edgeStrong, lineWidth: 1)
                )
                .opacity(isEnabled ? (configuration.isPressed ? 0.7 : 1) : 0.5)
        }
    }
}

/// A gold button that shows progress in place of its title while its action runs.
struct PrimaryButton: View {
    let title: String
    var busy = false
    let action: @MainActor () -> Void

    var body: some View {
        Button {
            action()
        } label: {
            ZStack {
                Text(title).opacity(busy ? 0 : 1)
                if busy {
                    ProgressView().tint(Palette.buttonInk)
                }
            }
        }
        .buttonStyle(PrimaryButtonStyle())
    }
}

/// A copy button whose icon turns to a check for a moment after it is used.
struct CopyButton: View {
    let label: String
    let copied: Bool
    let action: @MainActor () -> Void

    var body: some View {
        Button {
            action()
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .contentTransition(.symbolEffect(.replace))
                .foregroundStyle(copied ? Palette.ok : Palette.goldText)
                .frame(minWidth: 32, minHeight: 32)
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(label)
    }
}

/// A checkbox row, for an acknowledgment.
struct CheckToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                    .foregroundStyle(configuration.isOn ? Palette.gold : Palette.inkFaint)
                configuration.label
                    .font(.subheadline)
                    .foregroundStyle(Palette.ink)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "Checked" : "Not checked")
    }
}

// MARK: - Fields

/// A field's small capitals label. The field itself carries the same words for VoiceOver.
struct FieldLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.caption.weight(.medium))
            .tracking(0.6)
            .foregroundStyle(Palette.inkFaint)
            .accessibilityHidden(true)
    }
}

private struct FieldBox: ViewModifier {
    let focused: Bool

    func body(content: Content) -> some View {
        content
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .background(Palette.input, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(focused ? Palette.gold : Palette.edge, lineWidth: 1)
            )
    }
}

extension View {
    func fieldBox(focused: Bool = false) -> some View {
        modifier(FieldBox(focused: focused))
    }
}

/// A labelled text field in the treasury style. Passwords use secure entry, and every field says what it
/// holds so iOS can fill andvari's own sign-in.
struct InputField<Focus: Hashable>: View {
    private let label: String
    @Binding private var text: String
    private let focus: FocusState<Focus?>.Binding
    private let field: Focus
    private let prompt: String?
    private let secure: Bool
    private let monospaced: Bool
    private let contentType: UITextContentType?
    private let keyboard: UIKeyboardType
    private let capitalization: TextInputAutocapitalization
    private let submitLabel: SubmitLabel
    private let onSubmit: @MainActor () -> Void

    init(
        _ label: String,
        text: Binding<String>,
        focus: FocusState<Focus?>.Binding,
        field: Focus,
        prompt: String? = nil,
        secure: Bool = false,
        monospaced: Bool = false,
        contentType: UITextContentType? = nil,
        keyboard: UIKeyboardType = .default,
        capitalization: TextInputAutocapitalization = .never,
        submitLabel: SubmitLabel = .next,
        onSubmit: @escaping @MainActor () -> Void = {}
    ) {
        self.label = label
        _text = text
        self.focus = focus
        self.field = field
        self.prompt = prompt
        self.secure = secure
        self.monospaced = monospaced
        self.contentType = contentType
        self.keyboard = keyboard
        self.capitalization = capitalization
        self.submitLabel = submitLabel
        self.onSubmit = onSubmit
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(text: label)
            entry
                .font(monospaced ? Font.body.monospaced() : Font.body)
                .foregroundStyle(Palette.ink)
                .tint(Palette.gold)
                .textContentType(contentType)
                .keyboardType(keyboard)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled()
                .submitLabel(submitLabel)
                .focused(focus, equals: field)
                .onSubmit { onSubmit() }
                .fieldBox(focused: focus.wrappedValue == field)
        }
    }

    @ViewBuilder private var entry: some View {
        if secure {
            SecureField(label, text: $text, prompt: Text(prompt ?? ""))
        } else {
            TextField(label, text: $text, prompt: Text(prompt ?? ""))
        }
    }
}

// MARK: - Messages

/// A tinted plate for an error or a notice, with a dismiss button.
struct Plate: View {
    enum Tone {
        case error
        case notice
    }

    let text: String
    let tone: Tone
    let onDismiss: @MainActor () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(text)
                .font(.subheadline)
                .foregroundStyle(color)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                onDismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.footnote.weight(.semibold))
                    .frame(minWidth: 32, minHeight: 32)
            }
            .buttonStyle(.borderless)
            .foregroundStyle(color)
            .accessibilityLabel("Dismiss")
        }
        .padding(.leading, 14)
        .padding(.trailing, 4)
        .padding(.vertical, 4)
        .background {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Palette.raised)
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(color.opacity(0.12)))
        }
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(color.opacity(0.3), lineWidth: 1)
        )
        .onChange(of: text, initial: true) {
            AccessibilityNotification.Announcement(text).post()
        }
    }

    private var color: Color {
        tone == .error ? Palette.danger : Palette.goldBright
    }
}

/// A sentence under a form: why the last action did not go through.
struct InlineMessage: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(Palette.danger)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .onChange(of: text, initial: true) {
                AccessibilityNotification.Announcement(text).post()
            }
    }
}

// MARK: - Layout

/// The scrolling column the sign-in screens share.
struct AuthScroll<Content: View>: View {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                content
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: 460)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}
