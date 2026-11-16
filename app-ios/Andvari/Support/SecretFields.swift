import SwiftUI
import UIKit

// Fields for secrets: a recovery phrase, a password or card number shown while it is edited, a note. Each has
// autocorrection, spell checking, smart punctuation, inline predictions, capitalization and Writing Tools off, so the
// keyboard neither rewrites what is typed (a smart dash in a base64url phrase is a different phrase) nor learns it into
// its dictionary or suggestions, and nothing offers to send it off to be rewritten. SwiftUI's TextField and TextEditor
// can turn off autocorrection only, so these are UIKit views. A hidden secret is a secure text entry, which iOS types
// with the system keyboard only and never learns. Keyboards from other apps are kept out of the whole app
// (AppDelegate, ThirdPartyKeyboards): they need not honour any of these traits.

/// What every secret field turns off.
@MainActor
private func harden(_ field: UITextField) {
    field.autocorrectionType = .no
    field.spellCheckingType = .no
    field.smartQuotesType = .no
    field.smartDashesType = .no
    field.smartInsertDeleteType = .no
    field.autocapitalizationType = .none
    field.inlinePredictionType = .no
    if #available(iOS 18.0, *) {
        field.writingToolsBehavior = .none
    }
}

@MainActor
private func harden(_ view: UITextView) {
    view.autocorrectionType = .no
    view.spellCheckingType = .no
    view.smartQuotesType = .no
    view.smartDashesType = .no
    view.smartInsertDeleteType = .no
    view.autocapitalizationType = .none
    view.inlinePredictionType = .no
    if #available(iOS 18.0, *) {
        view.writingToolsBehavior = .none
    }
}

private func bodyFont(monospaced: Bool) -> UIFont {
    let size = UIFont.preferredFont(forTextStyle: .body).pointSize
    let font = monospaced ? UIFont.monospacedSystemFont(ofSize: size, weight: .regular) : UIFont.systemFont(ofSize: size)
    return UIFontMetrics(forTextStyle: .body).scaledFont(for: font)
}

/// A one-line secret, hidden ([secure]) or shown.
struct SecretTextField: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String = ""
    var secure: Bool
    var monospaced: Bool = true
    var keyboard: UIKeyboardType = .asciiCapable
    var contentType: UITextContentType?
    var returnKey: UIReturnKeyType = .default
    /// Whether the field should hold the keyboard, for a caller that moves the keyboard itself (InputField's focus): the
    /// field follows a CHANGE of it, never its value alone, so a caller that leaves it at false (the editors) never takes
    /// the keyboard from a field being typed in. [onFocusChange] reports what the field does.
    var focused: Bool = false
    var onFocusChange: (Bool) -> Void = { _ in }
    var onSubmit: () -> Void = {}

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> UITextField {
        let field = UITextField()
        field.delegate = context.coordinator
        field.addTarget(context.coordinator, action: #selector(Coordinator.changed(_:)), for: .editingChanged)
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.adjustsFontForContentSizeCategory = true
        harden(field)
        return field
    }

    func updateUIView(_ field: UITextField, context: Context) {
        context.coordinator.parent = self
        if field.isSecureTextEntry != secure {
            field.isSecureTextEntry = secure
        }
        if field.text != text {
            field.text = text
        }
        field.placeholder = placeholder
        field.keyboardType = keyboard
        field.textContentType = contentType
        field.returnKeyType = returnKey
        field.font = bodyFont(monospaced: monospaced)
        field.textColor = UIColor(Palette.ink)
        field.tintColor = UIColor(Palette.gold)
        // Every key typed changes the binding, and every change runs this update. Focus is therefore applied only when the
        // caller's request changes: an update that merely repeats "false" must never resign the field the person is typing
        // in (it did, after every key, in the login and card editors, which pass no focus at all). The first update asks
        // for the keyboard only when the caller wants it, and resigns nothing.
        let coordinator = context.coordinator
        if coordinator.requestedFocus != focused {
            let first = coordinator.requestedFocus == nil
            coordinator.requestedFocus = focused
            if focused {
                DispatchQueue.main.async {
                    if coordinator.requestedFocus == true, !field.isFirstResponder { field.becomeFirstResponder() }
                }
            } else if !first {
                DispatchQueue.main.async {
                    if coordinator.requestedFocus == false, field.isFirstResponder { field.resignFirstResponder() }
                }
            }
        }
    }

    @MainActor
    final class Coordinator: NSObject, UITextFieldDelegate {
        var parent: SecretTextField
        /// The caller's focus request as last applied; nil before the first update.
        var requestedFocus: Bool?

        init(_ parent: SecretTextField) {
            self.parent = parent
        }

        @objc func changed(_ field: UITextField) {
            parent.text = field.text ?? ""
        }

        func textFieldShouldReturn(_ field: UITextField) -> Bool {
            parent.onSubmit()
            return false
        }

        func textFieldDidBeginEditing(_ field: UITextField) {
            parent.onFocusChange(true)
        }

        func textFieldDidEndEditing(_ field: UITextField) {
            parent.onFocusChange(false)
        }
    }
}

/// A secret of several lines: a note.
struct SecretTextEditor: UIViewRepresentable {
    @Binding var text: String
    var monospaced: Bool = false

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        view.backgroundColor = .clear
        view.adjustsFontForContentSizeCategory = true
        view.textContainerInset = UIEdgeInsets(top: 6, left: 0, bottom: 6, right: 0)
        view.textContainer.lineFragmentPadding = 0
        harden(view)
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        context.coordinator.parent = self
        if view.text != text {
            view.text = text
        }
        view.font = bodyFont(monospaced: monospaced)
        view.textColor = UIColor(Palette.ink)
        view.tintColor = UIColor(Palette.gold)
    }

    @MainActor
    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: SecretTextEditor

        init(_ parent: SecretTextEditor) {
            self.parent = parent
        }

        func textViewDidChange(_ view: UITextView) {
            parent.text = view.text ?? ""
        }
    }
}
