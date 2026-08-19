import AppKit
import VaultCore

/// NSPasteboard adapter: concealed + transient marker types, current-host-only (no Universal Clipboard).
final class SystemPasteboard: VaultCore.Pasteboard, @unchecked Sendable {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    func writeConcealed(_ string: String) -> Int {
        let pb = NSPasteboard.general
        _ = pb.prepareForNewContents(with: .currentHostOnly)
        let item = NSPasteboardItem()
        item.setString(string, forType: .string)
        item.setData(Data(), forType: Self.concealed)
        item.setData(Data(), forType: Self.transient)
        pb.writeObjects([item])
        return pb.changeCount
    }
    var changeCount: Int { NSPasteboard.general.changeCount }
    func clear() { NSPasteboard.general.clearContents() }
}
