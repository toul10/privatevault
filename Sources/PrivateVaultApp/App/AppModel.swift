import AppKit
import SwiftUI
import VaultCore

/// Top-level application state. Owns the VaultManager, the current session, auto-lock, clipboard and settings.
/// UI code never sees keys; it only sees `VaultItem`s from the session and calls high-level operations here.
@MainActor @Observable
final class AppModel {
    enum Phase: Equatable {
        case loading
        case noVault          // onboarding
        case recoveryKit      // vault just created: the kit MUST be shown/confirmed before the main UI appears
        case locked
        case unlocked
    }

    let manager: VaultManager
    let settings: AppSettings
    let clipboard: SecureClipboard
    let authenticator: Authenticator
    private(set) var phase: Phase = .loading
    private(set) var session: VaultSession?
    private(set) var items: [VaultItem] = []
    private(set) var integrityWarnings: [IntegrityWarning] = []
    private(set) var biometricAvailable = false
    private(set) var biometricEnabled = false
    private(set) var secretKeyOnDevice = true
    /// Set right after vault creation until the user confirms they saved the kit.
    private(set) var pendingRecoveryKit: CreatedVault?
    var lastError: String?
    var clipboardClearAt: Date?

    private var autoLock: AutoLockController!
    private var lockTriggers: LockTriggers?

    static let vaultDirectoryName = "PrivateVault/Vault.noindex"

    init(manager: VaultManager? = nil, settings: AppSettings = AppSettings(), pasteboard: VaultCore.Pasteboard = SystemPasteboard(),
         authenticator: Authenticator = SystemAuthenticator(), enclave: SecureEnclaveService = SystemSecureEnclave()) {
        self.settings = settings
        self.authenticator = authenticator
        let clock = SystemClock()
        self.clipboard = SecureClipboard(pasteboard: pasteboard, clock: clock, timeout: TimeInterval(settings.clipboardSeconds))
        if let manager {
            self.manager = manager
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            let url = base.appendingPathComponent(Self.vaultDirectoryName).appendingPathComponent(VaultStore.fileName)
            self.manager = VaultManager(vaultURL: url, deviceKeys: DeviceKeyStore(store: KeychainSecretStore(), enclave: enclave))
        }
        self.autoLock = AutoLockController(policy: AutoLockPolicy(timeout: settings.autoLock), clock: clock) { [weak self] in
            Task { @MainActor in await self?.lock() }
        }
        self.lockTriggers = LockTriggers(controller: autoLock)
        self.biometricAvailable = authenticator.biometryAvailable && enclave.isAvailable
        // Windows created later (Settings, sheets) must get the same capture policy.
        windowObserver = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                for w in NSApp.windows { w.isRestorable = false }   // no UI state of any window is ever persisted
                self?.applyWindowSharing()
            }
        }
        AppDelegate.terminateHandler = { [weak self] in
            self?.clipboard.clearIfStillOurs()
            self?.items = []
        }
        Task { await refreshPhase() }
    }
    private var windowObserver: Any?

    // MARK: phase
    func refreshPhase() async {
        if pendingRecoveryKit != nil { phase = .recoveryKit; return }
        if let session, await !session.isLocked { phase = .unlocked; return }
        phase = manager.vaultExists ? .locked : .noVault
        biometricEnabled = await manager.isBiometricUnlockEnabled()
        secretKeyOnDevice = await manager.secretKeyAvailableOnDevice()
    }

    // MARK: onboarding
    struct CreatedVault: Equatable { let recoveryKit: String; let secretKeyStoredOnDevice: Bool }
    /// Creates the vault and parks the app in `.recoveryKit` until `confirmRecoveryKitSaved()`.
    func createVault(password: String) async throws {
        let result = try await manager.createVault(password: password)
        await adopt(session: result.session, phase: .recoveryKit)
        pendingRecoveryKit = CreatedVault(recoveryKit: RecoveryKit.encode(result.secretKey), secretKeyStoredOnDevice: result.secretKeyStoredOnDevice)
        settings.hasCompletedOnboarding = true
    }
    func confirmRecoveryKitSaved() {
        pendingRecoveryKit = nil
        if session != nil { phase = .unlocked; applyWindowSharing() }
    }

    // MARK: unlock / lock
    func unlock(password: String, recoveryKit: String? = nil) async throws {
        let s = try await manager.unlock(password: password, recoveryKit: recoveryKit)
        await adopt(session: s)
    }
    func unlockWithBiometrics() async throws {
        let s = try await manager.unlockWithBiometrics(reason: "Unlock PrivateVault")
        await adopt(session: s)
    }
    private func adopt(session s: VaultSession, phase newPhase: Phase = .unlocked) async {
        session = s
        integrityWarnings = await s.integrityWarnings
        await reloadItems()
        biometricEnabled = await manager.isBiometricUnlockEnabled()
        secretKeyOnDevice = await manager.secretKeyAvailableOnDevice()
        autoLock.update(policy: AutoLockPolicy(timeout: settings.autoLock))
        autoLock.arm()
        phase = newPhase
        applyWindowSharing()
    }
    func lock() async {
        autoLock.disarm()
        lastSecretAuth = nil
        clipboard.clearIfStillOurs(); clipboardClearAt = nil
        items = []            // drop plaintext from the UI model before anything else
        integrityWarnings = []
        pendingRecoveryKit = nil
        await manager.lock()
        session = nil
        phase = manager.vaultExists ? .locked : .noVault
        applyWindowSharing()
    }
    func noteActivity() { autoLock.handle(.userActivity) }
    func settingsChanged() {
        autoLock.update(policy: AutoLockPolicy(timeout: settings.autoLock))
        clipboard.timeout = TimeInterval(settings.clipboardSeconds)
        applyWindowSharing()
    }
    /// Block screen capture / screen sharing of our windows whenever secrets can be on screen (optional, default on).
    func applyWindowSharing() {
        let block = settings.blockScreenCapture && (phase == .unlocked || phase == .recoveryKit)
        for w in NSApp.windows { w.sharingType = block ? .none : .readOnly }
    }

    // MARK: items
    func reloadItems() async {
        guard let session else { items = []; return }
        items = (try? await session.allItems()) ?? []
    }
    func save(_ item: VaultItem) async throws {
        guard let session else { throw VaultError.vaultLocked }
        try await session.save(item)
        await reloadItems()
    }
    func delete(_ id: UUID) async throws {
        guard let session else { throw VaultError.vaultLocked }
        try await session.delete(id)
        await reloadItems()
    }
    func toggleFavorite(_ id: UUID) async {
        guard let session, let item = items.first(where: { $0.id == id }) else { return }
        try? await session.setFavorite(id, !item.favorite)
        await reloadItems()
    }
    func markUsed(_ id: UUID) async {
        guard let session else { return }
        try? await session.markUsed(id)
        await reloadItems()
    }

    // MARK: secrets to the user
    static let secretAuthGrace: TimeInterval = 30
    private var lastSecretAuth: Date?
    /// Tier-1 gate (passwords, API keys, notes, recovery codes): Touch ID / login password unless authenticated
    /// within the last 30 s. Disabled by the "Require Touch ID for secrets" setting. UI/policy gate (§8.3).
    func authorizeSecretAccess(reason: String = "Show a stored secret") async throws {
        guard settings.requireAuthForSecrets else { return }
        if let t = lastSecretAuth, Date().timeIntervalSince(t) < Self.secretAuthGrace { return }
        try await authenticator.authenticate(reason: reason)
        lastSecretAuth = Date()
    }
    /// Explicit user copy. Schedules the auto-clear.
    func copySecret(_ value: String, itemID: UUID?) {
        clipboardClearAt = clipboard.copy(value)
        if let itemID { Task { await markUsed(itemID) } }
    }
    /// Tier-2 reveal: system authentication first, then decrypt the inner box.
    func revealTier2(itemID: UUID, field: RecordCodec.Tier2Field) async throws -> String? {
        guard let session else { throw VaultError.vaultLocked }
        try await authenticator.authenticate(reason: field == .seedPhrase ? "Reveal the wallet seed phrase" : "Reveal the wallet private key")
        return try await session.revealTier2(itemID: itemID, field: field)
    }

    // MARK: security settings
    func enableBiometricUnlock() async throws {
        try await manager.enableBiometricUnlock(); biometricEnabled = true
    }
    func disableBiometricUnlock(password: String) async throws {
        try await manager.disableBiometricUnlock(password: password); biometricEnabled = false
    }
    func changePassword(current: String, new: String, rotateKeys: Bool) async throws {
        try await manager.changePassword(current: current, new: new, rotateKeys: rotateKeys)
        await reloadItems()
    }
    func regenerateSecretKey(password: String) async throws -> CreatedVault {
        let r = try await manager.regenerateSecretKey(password: password)
        secretKeyOnDevice = await manager.secretKeyAvailableOnDevice()
        await reloadItems()
        return CreatedVault(recoveryKit: RecoveryKit.encode(r.secretKey), secretKeyStoredOnDevice: r.secretKeyStoredOnDevice)
    }
    /// True when the Secret Key at rest is Secure-Enclave-wrapped; false on Macs without a Secure Enclave (raw in Keychain).
    var secretKeyHardwareBound: Bool { manager.deviceKeys.secretKeyIsHardwareBound }
    /// Ids of records that could not be decrypted at unlock (tampered/corrupted).
    var unreadableRecordCount: Int { get async { await session?.unreadableRecordIDs.count ?? 0 } }
    func purgeUnreadableRecords() async throws {
        guard let session else { throw VaultError.vaultLocked }
        try await session.purgeUnreadableRecords()
        integrityWarnings = await session.integrityWarnings
    }
    func inspectBackup(_ data: Data) throws -> (createdAt: Date, recordCount: Int) {
        let r = try manager.inspectBackup(data)
        return (r.createdAt, r.recordCount)
    }
    func recoveryKit(password: String) async throws -> String { try await manager.recoveryKit(password: password) }
    func exportBackup(password: String) async throws -> Data { try await manager.exportBackup(password: password) }
    func restoreBackup(_ data: Data, password: String, recoveryKit: String?) async throws {
        let s = try await manager.restoreBackup(data, password: password, recoveryKit: recoveryKit)
        settings.hasCompletedOnboarding = true
        await adopt(session: s)
    }
    func deleteVault(password: String) async throws {
        try await manager.deleteVault(password: password)
        await lock()
    }
}

extension VaultError {
    /// Short, non-secret, user-facing text.
    var userMessage: String {
        switch self {
        case .authenticationFailed: return "Wrong Master Password (or Secret Key), or the vault was tampered with."
        case .invalidHeader: return "The vault header is invalid or was modified."
        case .unsupportedFormat: return "This vault or backup was created by a newer version of PrivateVault."
        case .corrupted(let what): return "The vault file is corrupted (\(what))."
        case .kdfFailed: return "Key derivation failed (not enough memory?)."
        case .keychain(let code): return "Keychain error \(code)."
        case .keychainUnavailable: return "The Keychain is unavailable. You will need your Recovery Kit."
        case .secureEnclaveUnavailable: return "This Mac has no Secure Enclave available."
        case .secureEnclaveFailed: return "Secure Enclave operation failed."
        case .biometryUnavailable: return "Touch ID is not available right now. Use your Master Password."
        case .biometryInvalidated: return "Touch ID settings changed. Unlock with your Master Password and re-enable Touch ID."
        case .userCancelled: return "Cancelled."
        case .storage(let what): return "Storage error (\(what))."
        case .backupInvalid(let what): return "Backup rejected: \(what)."
        case .recoveryKitInvalid(let what): return "Recovery Kit problem: \(what)."
        case .vaultLocked: return "The vault is locked."
        case .secretKeyRequired: return "Your Secret Key is not on this Mac. Enter your Recovery Kit."
        case .vaultAlreadyExists: return "A vault already exists."
        case .vaultNotFound: return "No vault found."
        case .invalidInput(let what): return what
        }
    }
}
func describe(_ error: Error) -> String { (error as? VaultError)?.userMessage ?? "Unexpected error." }
