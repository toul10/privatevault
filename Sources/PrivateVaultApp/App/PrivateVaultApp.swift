import AppKit
import SwiftUI
import VaultCore

@main
struct PrivateVaultApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup("PrivateVault") {
            RootView()
                .environment(model)
                .frame(minWidth: 900, minHeight: 560)
                .onAppear { model.applyWindowSharing() }
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 1100, height: 700)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Vault") {
                Button("Lock Vault") { Task { await model.lock() } }
                    .keyboardShortcut("l", modifiers: [.command])
                    .disabled(model.phase != .unlocked)
            }
        }
        Settings {
            SettingsView().environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Set by AppModel: synchronous cleanup (clipboard) that must happen before the process exits.
    nonisolated(unsafe) static var terminateHandler: (@MainActor () -> Void)?

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.terminateHandler?() }
    }
    func applicationWillFinishLaunching(_ notification: Notification) {
        // No core dumps (process memory holds secrets while unlocked).
        var lim = rlimit(rlim_cur: 0, rlim_max: 0)
        setrlimit(RLIMIT_CORE, &lim)
        // No window/state restoration: nothing about the UI state may be persisted.
        UserDefaults.standard.set(false, forKey: "NSQuitAlwaysKeepsWindows")
        let savedState = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Saved Application State")
        if let savedState, let entries = try? FileManager.default.contentsOfDirectory(at: savedState, includingPropertiesForKeys: nil) {
            for e in entries where e.lastPathComponent.hasPrefix("com.kostastoulis.privatevault") { try? FileManager.default.removeItem(at: e) }
        }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        for w in NSApp.windows { w.isRestorable = false }
    }
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { for w in NSApp.windows { w.makeKeyAndOrderFront(nil) } }
        return true
    }
}
