import SwiftUI
import AppKit
import VaultCore

/// NSTextView that routes Copy/Cut through SecureClipboard (concealed, auto-clearing) and refuses drag-out.
final class SecretTextView: NSTextView {
    var secureCopy: ((String) -> Void)?
    private var selectedText: String? {
        let r = selectedRange()
        guard r.length > 0, let s = (string as NSString?)?.substring(with: r) else { return nil }
        return s
    }
    override func copy(_ sender: Any?) { if let t = selectedText { secureCopy?(t) } }
    override func cut(_ sender: Any?) {
        if let t = selectedText { secureCopy?(t); insertText("", replacementRange: selectedRange()) }
    }
    override func draggingSession(_ session: NSDraggingSession, sourceOperationMaskFor context: NSDraggingContext) -> NSDragOperation { [] }
    override func writeSelection(to pboard: NSPasteboard, types: [NSPasteboard.PasteboardType]) -> Bool { false }
    // Services menu / "Share" / "Look Up" would hand the selection to other processes: disable.
    override func validRequestor(forSendType sendType: NSPasteboard.PasteboardType?, returnType: NSPasteboard.PasteboardType?) -> Any? { nil }
    override func menu(for event: NSEvent) -> NSMenu? {
        let m = NSMenu()
        m.addItem(withTitle: "Cut", action: #selector(cut(_:)), keyEquivalent: "x")
        m.addItem(withTitle: "Copy (auto-clears)", action: #selector(copy(_:)), keyEquivalent: "c")
        m.addItem(withTitle: "Paste", action: #selector(paste(_:)), keyEquivalent: "v")
        m.addItem(withTitle: "Select All", action: #selector(selectAll(_:)), keyEquivalent: "a")
        return m
    }
}

/// Text entry for secrets: no autocorrect, no spell-check, no inline predictions, no Writing Tools, secure copy.
struct PlainSecretTextEditor: NSViewRepresentable {
    @Environment(AppModel.self) private var model
    @Binding var text: String
    var monospaced = true
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        let tv = SecretTextView(frame: .zero)
        tv.autoresizingMask = [.width]
        tv.isVerticallyResizable = true
        tv.isHorizontallyResizable = false
        tv.textContainer?.widthTracksTextView = true
        tv.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        tv.minSize = NSSize(width: 0, height: 0)
        tv.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        scroll.documentView = tv
        tv.secureCopy = { [model] value in model.copySecret(value, itemID: nil) }
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
        tv.importsGraphics = false
        tv.isAutomaticLinkDetectionEnabled = false
        tv.isAutomaticDataDetectionEnabled = false
        tv.font = monospaced ? .monospacedSystemFont(ofSize: 13, weight: .regular) : .systemFont(ofSize: 13)
        tv.textContainerInset = NSSize(width: 6, height: 8)
        tv.inlinePredictionType = .no                       // macOS 14+: no predictive text / LM learning
        if #available(macOS 15.0, *) { tv.writingToolsBehavior = .none; tv.mathExpressionCompletionType = .no }
        tv.setAccessibilityProtectedContent(true)
        scroll.borderType = .bezelBorder
        tv.string = text
        return scroll
    }
    func updateNSView(_ nsView: NSScrollView, context: Context) {
        guard let tv = nsView.documentView as? NSTextView else { return }
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

/// Single-line text field for Recovery-Kit style input: no autocorrect, no spell-check, no predictions, no Writing Tools.
struct PlainSecretTextField: NSViewRepresentable {
    let placeholder: String
    @Binding var text: String
    var monospaced = false
    func makeNSView(context: Context) -> NSTextField {
        let f = NSTextField(string: text)
        f.placeholderString = placeholder
        f.delegate = context.coordinator
        f.isBezeled = true; f.bezelStyle = .roundedBezel
        f.font = monospaced ? .monospacedSystemFont(ofSize: 13, weight: .regular) : .systemFont(ofSize: 13)
        f.allowsEditingTextAttributes = false
        f.setAccessibilityProtectedContent(true)
        return f
    }
    func updateNSView(_ f: NSTextField, context: Context) {
        if f.stringValue != text { f.stringValue = text }
        if let editor = f.currentEditor() as? NSTextView { Self.harden(editor) }
    }
    static func harden(_ tv: NSTextView) {
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isAutomaticTextCompletionEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        tv.isGrammarCheckingEnabled = false
        tv.inlinePredictionType = .no
        if #available(macOS 15.0, *) { tv.writingToolsBehavior = .none }
    }
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: PlainSecretTextField
        init(_ p: PlainSecretTextField) { parent = p }
        func controlTextDidChange(_ n: Notification) {
            guard let f = n.object as? NSTextField else { return }
            parent.text = f.stringValue
        }
        func controlTextDidBeginEditing(_ n: Notification) {
            if let f = n.object as? NSTextField, let editor = f.currentEditor() as? NSTextView { PlainSecretTextField.harden(editor) }
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
                            .textSelection(.disabled)   // copying goes through SecureClipboard only (Copy button)
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
                .textSelection(.disabled)   // never on the clipboard: write it down or use "Save as text file…"
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
