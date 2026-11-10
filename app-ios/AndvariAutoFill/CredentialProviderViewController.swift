import AndvariCore
import AuthenticationServices
import UIKit

/** Placeholder until the vault snapshot exists: proves the extension loads and can use the core. */
final class CredentialProviderViewController: ASCredentialProviderViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let label = UILabel()
        label.text = "andvari \(AndvariBridge.shared.coreVersion())\nAutoFill is not ready yet."
        label.numberOfLines = 0
        label.textAlignment = .center

        let close = UIButton(type: .system, primaryAction: UIAction(title: "Close") { [weak self] _ in self?.cancel() })

        let stack = UIStackView(arrangedSubviews: [label, close])
        stack.axis = .vertical
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.layoutMarginsGuide.leadingAnchor),
        ])
    }

    private func cancel() {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
}
