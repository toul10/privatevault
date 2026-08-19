import SwiftUI
import AppKit
import VaultCore

/// Text entry for secrets: no autocorrect, no spell-check, no inline predictions, no Writing Tools.
struct PlainSecretTextEditor: NSViewRepresentable {
    @Binding var text: String
    var monospaced = true
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let tv = scroll.documentView as! NSTextView
        tv.delegate = context.coordinator
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isAutomaticTextCompletionEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        tv.isGrammarCheckingEnabled = false
        tv.allowsUndo = false
        tv.usesFindPanel = false
        tv.isRichText = false
        tv.font = monospaced ? .monospacedSystemFont(ofSize: 13, weight: .regular) : .systemFont(ofSize: 13)
        tv.textContainerInset = NSSize(width: 6, height: 8)
        if #available(macOS 15.0, *) { tv.writingToolsBehavior = .none }
        tv.setAccessibilityProtectedContent(true)
        scroll.borderType = .bezelBorder
        tv.string = text
        return scroll
    }
    func updateNSView(_ nsView: NSScrollView, context: Context) {
        let tv = nsView.documentView as! NSTextView
        if tv.string != text { tv.string = text }
    }
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: PlainSecretTextEditor
        init(_ p: PlainSecretTextEditor) { parent = p }
        func textDidChange(_ notification: Notification) {
            guard let tv = notification.object as? NSTextView else { return }
            parent.text = tv.string
        }
    }
}

/// Masked value with Reveal/Hide and Copy. Used for passwords, API keys, secrets, recovery codes, notes.
struct SecretRow: View {
    @Environment(AppModel.self) private var model
    let label: String
    let value: String
    var itemID: UUID? = nil
    var multiline = false
    var monospaced = true
    @State private var revealed = false

    var body: some View {
        LabeledContent {
            HStack(alignment: .top, spacing: 8) {
                Group {
                    if revealed {
                        Text(value).font(monospaced ? .system(.body, design: .monospaced) : .body)
                            .textSelection(.enabled)
                            .accessibilityProtectedContent()
                    } else {
                        Text(value.isEmpty ? "—" : String(repeating: "•", count: min(max(value.count, 8), 24)))
                            .font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(multiline ? nil : 1)
                if !value.isEmpty {
                    Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless).help(revealed ? "Hide" : "Reveal")
                    CopyButton(value: value, itemID: itemID)
                }
            }
        } label: { Text(label) }
        .onDisappear { revealed = false }
    }
}

/// Copies to the clipboard with auto-clear and shows a brief confirmation + countdown.
struct CopyButton: View {
    @Environment(AppModel.self) private var model
    let value: String
    var itemID: UUID? = nil
    var label: String? = nil
    @State private var copiedAt: Date? = nil
    var body: some View {
        Button {
            model.copySecret(value, itemID: itemID)
            copiedAt = Date()
        } label: {
            if let label { Label(label, systemImage: "doc.on.doc") } else { Image(systemName: copiedAt == nil ? "doc.on.doc" : "checkmark") }
        }
        .buttonStyle(.borderless)
        .help("Copy (clears automatically after \(model.settings.clipboardSeconds) s)")
        .task(id: copiedAt) {
            guard copiedAt != nil else { return }
            try? await Task.sleep(for: .seconds(1.5))
            copiedAt = nil
        }
    }
}

/// Small bar showing the clipboard auto-clear countdown.
struct ClipboardCountdownBar: View {
    @Environment(AppModel.self) private var model
    @State private var now = Date()
    var body: some View {
        Group {
            if let at = model.clipboardClearAt, at > now, model.clipboard.holdsOurSecret {
                HStack(spacing: 6) {
                    Image(systemName: "clipboard")
                    Text("Clipboard clears in \(Int(at.timeIntervalSince(now).rounded(.up))) s")
                    Spacer()
                    Button("Clear now") { model.clipboard.clearIfStillOurs(); model.clipboardClearAt = nil }.buttonStyle(.link)
                }
                .font(.caption).padding(.horizontal, 12).padding(.vertical, 6)
                .background(.thinMaterial)
            }
        }
        .task {
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(1)); now = Date() }
        }
    }
}

/// Master-password field (Secure Event Input) with an optional strength meter.
struct MasterPasswordField: View {
    let title: String
    @Binding var text: String
    var showStrength = false
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SecureField(title, text: $text).textFieldStyle(.roundedBorder)
            if showStrength {
                let s = PasswordStrength.estimate(text)
                HStack(spacing: 6) {
                    ProgressView(value: min(s.entropyBits, 100), total: 100).tint(color(s.rating)).frame(width: 140)
                    Text(text.isEmpty ? "" : "\(label(s.rating)) · ~\(Int(s.entropyBits)) bits").font(.caption).foregroundStyle(.secondary)
                    if PasswordNormalization.hasLeadingOrTrailingWhitespace(text) {
                        Text("has leading/trailing spaces").font(.caption).foregroundStyle(.orange)
                    }
                }
            }
        }
    }
    private func color(_ r: PasswordStrength.Rating) -> Color {
        switch r { case .veryWeak: .red; case .weak: .orange; case .fair: .yellow; case .strong: .green; case .veryStrong: .green }
    }
    private func label(_ r: PasswordStrength.Rating) -> String {
        switch r { case .veryWeak: "Very weak"; case .weak: "Weak"; case .fair: "Fair"; case .strong: "Strong"; case .veryStrong: "Very strong" }
    }
}

struct ErrorBanner: View {
    let message: String?
    var body: some View {
        if let message, !message.isEmpty {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct RecoveryKitView: View {
    let kit: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(kit)
                .font(.system(.title3, design: .monospaced).weight(.medium))
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.orange, lineWidth: 1.5))
                .accessibilityProtectedContent()
            Label("Write it on paper and store it somewhere safe (not on this Mac, not in a photo, not in iCloud). Anyone with this kit AND your Master Password can open your vault.", systemImage: "exclamationmark.triangle")
                .font(.callout).foregroundStyle(.orange)
        }
    }
}

extension View {
    @ViewBuilder func accessibilityProtectedContent() -> some View {
        self.accessibilityHidden(true) // screen readers/accessibility clients cannot read revealed secrets
    }
}
