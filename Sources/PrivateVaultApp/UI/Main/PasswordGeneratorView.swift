import SwiftUI
import VaultCore

struct PasswordGeneratorView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var onUse: ((String) -> Void)? = nil
    @State private var options = PasswordGenerator.Options()
    @State private var generated = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Password Generator").font(.title2.weight(.semibold))
            HStack {
                Text(generated.isEmpty ? " " : generated)
                    .font(.system(.title3, design: .monospaced)).textSelection(.enabled).lineLimit(2)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                    .accessibilityProtectedContent()
                Button { regenerate() } label: { Image(systemName: "arrow.clockwise") }.help("Generate again")
                CopyButton(value: generated)
            }
            let s = PasswordStrength.estimate(generated)
            Text("≈ \(Int(PasswordGenerator.entropyBits(options))) bits of entropy · \(s.rating.rawValue)").font(.caption).foregroundStyle(.secondary)
            Form {
                Stepper("Length: \(options.length)", value: $options.length, in: PasswordGenerator.minLength...PasswordGenerator.maxLength)
                Slider(value: Binding(get: { Double(options.length) }, set: { options.length = Int($0) }), in: Double(PasswordGenerator.minLength)...64, step: 1)
                Toggle("Uppercase (A–Z)", isOn: $options.uppercase)
                Toggle("Lowercase (a–z)", isOn: $options.lowercase)
                Toggle("Numbers (0–9)", isOn: $options.digits)
                Toggle("Symbols (!@#…)", isOn: $options.symbols)
                Toggle("Exclude ambiguous characters (0 O l 1 |)", isOn: $options.excludeAmbiguous)
            }
            .formStyle(.grouped)
            .onChange(of: options) { _, _ in regenerate() }
            ErrorBanner(message: error)
            HStack {
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                if let onUse { Button("Use this password") { onUse(generated); dismiss() }.buttonStyle(.borderedProminent).disabled(generated.isEmpty) }
            }
        }
        .padding(20).frame(width: 520)
        .onAppear(perform: regenerate)
    }
    private func regenerate() {
        do { generated = try PasswordGenerator.generate(options); error = nil }
        catch { generated = ""; self.error = describe(error) }
    }
}
