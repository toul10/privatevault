import Foundation
@testable import VaultCore

func hex(_ s: String) -> Data { Data(hexString: s)! }
func rep(_ v: UInt8, _ n: Int) -> Data { Data(repeating: v, count: n) }
let testVaultID = UUID(rawBytes: hex("0123456789abcdef0123456789abcdef"))!
let testRecordID = UUID(rawBytes: hex("fedcba9876543210fedcba9876543210"))!

extension SecretKey {
    static func test(_ fill: UInt8 = 0x11) -> SecretKey { try! SecretKey(bytes: SecureBytes(copying: rep(fill, 32))) }
}
extension VaultHeader {
    /// Fixed header used by golden tests: testing KDF params, salt 00..0f, generation 1, createdAt 1_700_000_000.
    static var fixture: VaultHeader {
        VaultHeader(vaultID: testVaultID, kdf: .testing, salt: hex("000102030405060708090a0b0c0d0e0f"),
                    generation: 1, createdAt: 1_700_000_000)
    }
}
