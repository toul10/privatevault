import AppKit
import CoreGraphics
import VaultCore

/// Wires macOS events to the auto-lock controller: sleep, screen lock, session switch, power off, termination,
/// local user activity, and a periodic system-idle check.
@MainActor
final class LockTriggers {
    private let controller: AutoLockController
    private var observers: [Any] = []
    private var eventMonitor: Any?
    private var idleTimer: Timer?

    init(controller: AutoLockController) {
        self.controller = controller
        let wc = NSWorkspace.shared.notificationCenter
        let pairs: [(Notification.Name, AutoLockPolicy.Event)] = [
            (NSWorkspace.willSleepNotification, .systemWillSleep),
            (NSWorkspace.screensDidSleepNotification, .screensDidSleep),
            (NSWorkspace.sessionDidResignActiveNotification, .sessionResignedActive),
            (NSWorkspace.willPowerOffNotification, .willPowerOff),
        ]
        for (name, event) in pairs {
            observers.append(wc.addObserver(forName: name, object: nil, queue: .main) { [controller] _ in controller.handle(event) })
        }
        // Undocumented but long-stable distributed notification posted by loginwindow when the screen locks.
        observers.append(DistributedNotificationCenter.default().addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [controller] _ in
            controller.handle(.screenLocked)
        })
        observers.append(NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [controller] _ in
            controller.handle(.appWillTerminate)
        })
        // Local (this app only) input monitor — no Input Monitoring permission needed.
        eventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel, .mouseMoved]) { [controller] e in
            controller.handle(.userActivity); return e
        }
        idleTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [controller] _ in
            let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
            controller.tick(systemIdleSeconds: idle)
        }
    }
    /// Stops observing. (Lives for the whole app lifetime in practice.)
    func invalidate() {
        for o in observers { NSWorkspace.shared.notificationCenter.removeObserver(o); NotificationCenter.default.removeObserver(o); DistributedNotificationCenter.default().removeObserver(o) }
        observers.removeAll()
        if let m = eventMonitor { NSEvent.removeMonitor(m); eventMonitor = nil }
        idleTimer?.invalidate(); idleTimer = nil
    }
}
