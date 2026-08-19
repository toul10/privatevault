import Testing
import Foundation
@testable import VaultCore

@Suite("Password change, key rotation, KDF upgrade, Touch ID, Secret Key regeneration, backup/restore", .serialized)
struct SecurityFlowsTests {
    private func readRecordBlobs(_ url: URL) throws -> [Data: Data] {
        let db = try SQLiteDatabase(path: url.path, create: false)
        defer { db.close() }
        return Dictionary(uniqueKeysWithValues: try db.query("SELECT id, blob FROM records", bind: { _ in }) { ($0.blob(0), $0.blob(1)) })
    }
    private func readHeader(_ url: URL) throws -> StoredHeader {
        let db = try SQLiteDatabase(path: url.path, create: false)
        defer { db.close() }
        return try db.query("SELECT canonical, wrapped_vmk, header_sha256, sk_id, state_mac FROM vault_header", bind: { _ in }) {
            StoredHeader(canonical: $0.blob(0), wrappedVMK: $0.blob(1), headerSHA256: $0.blob(2), skID: $0.blob(3), stateMAC: $0.blob(4))
        }[0]
    }

    @Test func change_password_rewrap_only_keeps_records_untouched() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        for item in TestEnv.sampleItems() { try await s.save(item) }
        let before = try readRecordBlobs(m.vaultURL)
        let hBefore = try readHeader(m.vaultURL)
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword)
        let after = try readRecordBlobs(m.vaultURL)
        let hAfter = try readHeader(m.vaultURL)
        #expect(before == after)                                   // no re-encryption
        #expect(hBefore.wrappedVMK != hAfter.wrappedVMK)           // new wrap
        #expect(try hAfter.header().generation == 2)
        #expect(try hAfter.header().salt != hBefore.header().salt)
        // session keeps working without relock
        #expect(try await s.count() == 5)
        var first = try await s.allItems()[0]; first.title += " (edited)"
        try await s.save(first)
        await m.lock()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
        let s2 = try await m.unlock(password: TestEnv.otherPassword)
        #expect(try await s2.count() == 5)
        #expect(await s2.integrityWarnings.isEmpty)
        // wrong current password is rejected
        await #expect(throws: VaultError.authenticationFailed) { try await m.changePassword(current: TestEnv.password, new: "another long password 123!") }
        // weak new password is rejected
        await #expect(throws: VaultError.self) { try await m.changePassword(current: TestEnv.otherPassword, new: "short") }
    }

    @Test func change_password_with_rotation_reencrypts_everything_and_revokes_old_header() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let s = created.session
        for item in TestEnv.sampleItems() { try await s.save(item) }
        let before = try readRecordBlobs(m.vaultURL)
        let oldHeader = try readHeader(m.vaultURL)
        let oldKeys = try await s.currentKeys()
        let oldVMK = oldKeys.vmk.copyData()
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword, rotateKeys: true)
        let after = try readRecordBlobs(m.vaultURL)
        #expect(Set(before.keys) == Set(after.keys))
        for (id, blob) in before { #expect(after[id] != blob) }   // every record re-encrypted
        let newKeys = try await s.currentKeys()
        #expect(newKeys.vmk.copyData() != oldVMK)
        #expect(oldKeys.vmk.copyData() == Data(count: 32))        // old VMK wiped
        // session still serves everything (tier-2 resealed)
        let wallet = try await s.allItems().first { $0.kind == .wallet }!
        #expect(try await s.revealTier2(itemID: wallet.id, field: .seedPhrase)?.hasPrefix("abandon") == true)
        // An attacker with the OLD header + OLD password + SK can recover the old VMK…
        let pw = try PasswordNormalization.normalize(TestEnv.password)
        let oldKEK = try KeyHierarchy.deriveKEK(password: pw, secretKey: created.secretKey, header: oldHeader.header())
        let recoveredOldVMK = try KeyHierarchy.unwrapVMK(oldHeader.wrappedVMK, kek: oldKEK, header: oldHeader.header())
        #expect(recoveredOldVMK.copyData() == oldVMK)
        // …but it decrypts NOTHING in the rotated vault
        let oldCodec = RecordCodec(keys: try VaultKeys(vaultID: oldHeader.header().vaultID, vmk: recoveredOldVMK))
        for (id, blob) in after {
            let rec = EncryptedRecord(id: UUID(rawBytes: id)!, cryptoVersion: 1, revision: 0, blob: blob)
            #expect(throws: VaultError.authenticationFailed) { _ = try oldCodec.open(rec) }
        }
        // and the old header transplanted back does not unlock the rotated records
        await m.lock()
        let db = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        try db.run("UPDATE vault_header SET canonical = ?, wrapped_vmk = ?") { $0.bind(1, oldHeader.canonical); $0.bind(2, oldHeader.wrappedVMK) }
        db.close()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
    }

    @Test func kdf_upgrade_on_unlock() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        try await s.save(TestEnv.sampleItems()[0])
        await m.lock()
        #expect(try readHeader(m.vaultURL).header().kdf == .testing)
        await m.setKDFPolicy(KDFParameters(memoryKiB: 16 * 1024, passes: 2, lanes: 2))
        let s2 = try await m.unlock(password: TestEnv.password)
        let h = try readHeader(m.vaultURL).header()
        #expect(h.kdf == KDFParameters(memoryKiB: 16 * 1024, passes: 2, lanes: 2))
        #expect(h.generation == 2)
        #expect(try await s2.count() == 1)
        #expect(await s2.integrityWarnings.isEmpty)
        await m.lock()
        // never downgrades
        await m.setKDFPolicy(.testing)
        _ = try await m.unlock(password: TestEnv.password)
        #expect(try readHeader(m.vaultURL).header().kdf == KDFParameters(memoryKiB: 16 * 1024, passes: 2, lanes: 2))
    }

    @Test func touch_id_enable_unlock_cancel_invalidate_and_survives_header_changes() async throws {
        let (m, store, enclave, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        try await s.save(TestEnv.sampleItems()[0])
        #expect(await !m.isBiometricUnlockEnabled())
        try await m.enableBiometricUnlock()
        #expect(await m.isBiometricUnlockEnabled())
        // the bio record never contains the VMK in clear
        let vmk = try await s.currentKeys().vmk.copyData()
        for a in store.allAccounts { #expect(store.rawValue(a)!.range(of: vmk) == nil) }
        await m.lock()
        // cancel ⇒ still locked
        enclave.cancelNext = true
        await #expect(throws: VaultError.userCancelled) { _ = try await m.unlockWithBiometrics() }
        #expect(await !m.isUnlocked)
        // success
        let s2 = try await m.unlockWithBiometrics()
        #expect(try await s2.count() == 1)
        #expect(enclave.biometryPromptCount == 2)
        // password change (re-wrap, generation bump) keeps Touch ID working (bio blob re-wrapped, no prompt)
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword)
        await m.lock()
        _ = try await m.unlockWithBiometrics()
        // rotation keeps Touch ID working too
        try await m.changePassword(current: TestEnv.otherPassword, new: TestEnv.password, rotateKeys: true)
        await m.lock()
        let s3 = try await m.unlockWithBiometrics()
        #expect(try await s3.count() == 1)
        await m.lock()
        // fingerprint set changed ⇒ biometryInvalidated ⇒ password still works
        enclave.biometryInvalidated = true
        await #expect(throws: VaultError.biometryInvalidated) { _ = try await m.unlockWithBiometrics() }
        _ = try await m.unlock(password: TestEnv.password)
        enclave.biometryInvalidated = false
        // disable requires the password and removes the record
        await #expect(throws: VaultError.authenticationFailed) { try await m.disableBiometricUnlock(password: TestEnv.otherPassword) }
        try await m.disableBiometricUnlock(password: TestEnv.password)
        #expect(await !m.isBiometricUnlockEnabled())
        await m.lock()
        await #expect(throws: VaultError.biometryUnavailable) { _ = try await m.unlockWithBiometrics() }
    }

    @Test func touch_id_does_not_store_master_password_anywhere() async throws {
        let (m, store, _, dir) = TestEnv.makeManager()
        _ = try await m.createVault(password: TestEnv.password)
        try await m.enableBiometricUnlock()
        for a in store.allAccounts { #expect(store.rawValue(a)!.range(of: Data(TestEnv.password.utf8)) == nil) }
        #expect(TestEnv.directoryContains(dir, anyOf: [TestEnv.password]).isEmpty)
    }

    @Test func regenerate_secret_key_rotates_and_invalidates_old_kit() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let oldKit = RecoveryKit.encode(created.secretKey)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        let before = try readRecordBlobs(m.vaultURL)
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.regenerateSecretKey(password: TestEnv.otherPassword) }
        let newSK = try await m.regenerateSecretKey(password: TestEnv.password)
        let newKit = RecoveryKit.encode(newSK)
        #expect(newKit != oldKit)
        let after = try readRecordBlobs(m.vaultURL)
        for (id, blob) in before { #expect(after[id] != blob) }
        #expect(try await m.recoveryKit(password: TestEnv.password) == newKit)
        await m.lock()
        // device has the new SK ⇒ unlock works
        let s = try await m.unlock(password: TestEnv.password)
        #expect(try await s.count() == 5)
        await m.lock()
        // remove device SK: old kit is rejected (different sk_id), new kit works
        try m.deviceKeys.deleteSecretKey(vaultID: await s.currentHeader.vaultID)
        await #expect(throws: VaultError.recoveryKitInvalid("this Recovery Kit does not belong to this vault")) { _ = try await m.unlock(password: TestEnv.password, recoveryKit: oldKit) }
        _ = try await m.unlock(password: TestEnv.password, recoveryKit: newKit)
    }

    @Test func recovery_kit_requires_password() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.recoveryKit(password: TestEnv.otherPassword) }
        #expect(try await m.recoveryKit(password: TestEnv.password) == RecoveryKit.encode(created.secretKey))
    }

    @Test func backup_export_restore_disaster_recovery() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let kit = RecoveryKit.encode(created.secretKey)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        try await m.enableBiometricUnlock()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.exportBackup(password: TestEnv.otherPassword) }
        let backup = try await m.exportBackup(password: TestEnv.password)
        // the backup contains no plaintext, no password, no secret key, no kit
        let hits = TestEnv.sentinels + [TestEnv.password, kit, created.secretKey.bytes.copyData().hexString]
        for h in hits { #expect(backup.range(of: Data(h.utf8)) == nil, "backup contains \(h.prefix(10))") }
        #expect(backup.range(of: created.secretKey.bytes.copyData()) == nil)

        // DISASTER: a brand-new Mac (fresh manager, fresh keychain, fresh enclave), only backup + password + kit
        let (m2, store2, _, _) = TestEnv.makeManager()
        await #expect(throws: VaultError.secretKeyRequired) { _ = try await m2.restoreBackup(backup, password: TestEnv.password) }
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m2.restoreBackup(backup, password: TestEnv.otherPassword, recoveryKit: kit) }
        await #expect(throws: VaultError.recoveryKitInvalid("this Recovery Kit does not belong to the vault in the backup")) {
            _ = try await m2.restoreBackup(backup, password: TestEnv.password, recoveryKit: RecoveryKit.encode(SecretKey.generate()))
        }
        let restored = try await m2.restoreBackup(backup, password: TestEnv.password, recoveryKit: kit)
        let items = try await restored.allItems()
        #expect(items.map(\.title).sorted() == TestEnv.sampleItems().map(\.title).sorted())
        #expect(await restored.integrityWarnings.isEmpty)
        let wallet = items.first { $0.kind == .wallet }!
        #expect(try await restored.revealTier2(itemID: wallet.id, field: .privateKey)?.hasPrefix("0xFAKEPRIVATEKEY") == true)
        // the new Mac now has the SK stored (SE-wrapped) and no stale Touch ID record
        #expect(store2.allAccounts.count == 1)
        await m2.lock()
        _ = try await m2.unlock(password: TestEnv.password)
        // restore over an EXISTING vault replaces it atomically
        let s3 = try await m2.session!.allItems()
        #expect(s3.count == 5)
        try await m2.session!.save(VaultItem(title: "extra", payload: .secureNote(SecureNotePayload(body: Secret("x")))))
        let again = try await m2.restoreBackup(backup, password: TestEnv.password)
        #expect(try await again.count() == 5)
    }

    @Test func corrupted_or_spliced_backups_are_rejected() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let kit = RecoveryKit.encode(created.secretKey)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        let backup = try await m.exportBackup(password: TestEnv.password)
        var doc = try JSONDecoder().decode(BackupCodec.Document.self, from: backup)
        func encode(_ d: BackupCodec.Document) throws -> Data { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return try e.encode(d) }
        let (m2, _, _, _) = TestEnv.makeManager()

        // truncated / garbage / wrong format
        await #expect(throws: VaultError.self) { _ = try await m2.restoreBackup(backup.prefix(backup.count / 2), password: TestEnv.password, recoveryKit: kit) }
        await #expect(throws: VaultError.backupInvalid("not a PrivateVault backup")) { _ = try await m2.restoreBackup(Data("{}".utf8), password: TestEnv.password, recoveryKit: kit) }
        // modified record blob
        var d1 = doc; d1.records[0].blob[10] ^= 1
        await #expect(throws: VaultError.backupInvalid("manifest mismatch (records or header altered)")) { _ = try await m2.restoreBackup(try encode(d1), password: TestEnv.password, recoveryKit: kit) }
        // dropped record
        var d2 = doc; d2.records.removeLast()
        await #expect(throws: VaultError.backupInvalid("manifest mismatch (records or header altered)")) { _ = try await m2.restoreBackup(try encode(d2), password: TestEnv.password, recoveryKit: kit) }
        // duplicated record
        var d3 = doc; d3.records.append(doc.records[0])
        await #expect(throws: VaultError.backupInvalid("duplicate record")) { _ = try await m2.restoreBackup(try encode(d3), password: TestEnv.password, recoveryKit: kit) }
        // createdAt altered (bound by manifest AAD)
        var d4 = doc; d4.createdAt += 1
        await #expect(throws: VaultError.backupInvalid("manifest authentication failed")) { _ = try await m2.restoreBackup(try encode(d4), password: TestEnv.password, recoveryKit: kit) }
        // header spliced from a later backup (after password change) into this record set
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword)
        let later = try await m.exportBackup(password: TestEnv.otherPassword)
        let laterDoc = try JSONDecoder().decode(BackupCodec.Document.self, from: later)
        var d5 = doc; d5.header = laterDoc.header
        await #expect(throws: VaultError.self) { _ = try await m2.restoreBackup(try encode(d5), password: TestEnv.otherPassword, recoveryKit: kit) }
        var d6 = laterDoc; d6.records = doc.records; d6.manifest = doc.manifest; d6.createdAt = doc.createdAt
        await #expect(throws: VaultError.self) { _ = try await m2.restoreBackup(try encode(d6), password: TestEnv.otherPassword, recoveryKit: kit) }
        // unsupported version
        var d7 = doc; d7.version = 9
        await #expect(throws: VaultError.unsupportedFormat(9)) { _ = try await m2.restoreBackup(try encode(d7), password: TestEnv.password, recoveryKit: kit) }
        // absurd KDF params in backup header are rejected before any KDF work
        var hdr = try VaultHeader.parse(canonical: doc.header.canonical); hdr.kdf = KDFParameters(memoryKiB: 2 * 1024 * 1024, passes: 1, lanes: 1)
        doc.header.canonical = hdr.canonicalBytes
        await #expect(throws: VaultError.backupInvalid("header")) { _ = try await m2.restoreBackup(try encode(doc), password: TestEnv.password, recoveryKit: kit) }
        // nothing was written on the target side by any of the failed restores
        #expect(!m2.vaultExists)
    }

    @Test func delete_vault_requires_password_and_removes_everything() async throws {
        let (m, store, _, _) = TestEnv.makeManager()
        _ = try await m.createVault(password: TestEnv.password)
        try await m.enableBiometricUnlock()
        await #expect(throws: VaultError.authenticationFailed) { try await m.deleteVault(password: TestEnv.otherPassword) }
        try await m.deleteVault(password: TestEnv.password)
        #expect(!m.vaultExists)
        #expect(store.allAccounts.isEmpty)
        await #expect(throws: VaultError.vaultNotFound) { _ = try await m.unlock(password: TestEnv.password) }
    }
}
