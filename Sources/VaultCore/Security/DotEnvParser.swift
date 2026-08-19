import Foundation

/// Minimal, safe parser for `.env`-style files: `KEY=VALUE`, optional `export `, quotes, `#` comments.
/// Pure function; the caller owns the plaintext and must not persist it anywhere except the vault.
public enum DotEnvParser {
    public struct Entry: Equatable, Sendable { public let key: String; public let value: String }

    public static func parse(_ text: String) -> [Entry] {
        var out: [Entry] = []
        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, key.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }) else { continue }
            var value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, let f = value.first, let l = value.last, (f == "\"" && l == "\"") || (f == "'" && l == "'") {
                value = String(value.dropFirst().dropLast())
            } else if let hash = value.firstIndex(of: "#"), value[value.index(before: hash)] == " " {
                value = value[..<hash].trimmingCharacters(in: .whitespaces)   // trailing comment
            }
            out.append(Entry(key: key, value: value))
        }
        return out
    }
}
