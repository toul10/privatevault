import Testing
import Foundation
@testable import VaultCore

/// Opt-in benchmark used to choose production Argon2id parameters on the owner's Mac:
///   PV_BENCH=1 Scripts/run-tests.sh -c release --filter KDFBenchmark
@Suite("KDF benchmark", .serialized, .enabled(if: ProcessInfo.processInfo.environment["PV_BENCH"] == "1"))
struct KDFBenchmark {
    @Test func benchmark_candidates() throws {
        let pw = try PasswordNormalization.normalize("benchmark password 1234")
        let salt = SecureRandom.bytes(16)
        let candidates: [KDFParameters] = [
            KDFParameters(memoryKiB: 64 * 1024, passes: 3, lanes: 1),
            KDFParameters(memoryKiB: 128 * 1024, passes: 3, lanes: 1),
            KDFParameters(memoryKiB: 128 * 1024, passes: 3, lanes: 4),
            KDFParameters(memoryKiB: 256 * 1024, passes: 3, lanes: 4),
            KDFParameters(memoryKiB: 256 * 1024, passes: 4, lanes: 4),
            KDFParameters(memoryKiB: 256 * 1024, passes: 6, lanes: 4),
            KDFParameters(memoryKiB: 512 * 1024, passes: 3, lanes: 4),
        ]
        for p in candidates {
            var times: [Double] = []
            for _ in 0..<3 {
                let t0 = Date()
                _ = try Argon2id.derive(password: pw, salt: salt, params: p)
                times.append(Date().timeIntervalSince(t0))
            }
            times.sort()
            print(String(format: "KDF m=%4d MiB t=%d p=%d  median %.3f s  (min %.3f max %.3f)", p.memoryKiB / 1024, p.passes, p.lanes, times[1], times[0], times[2]))
        }
        let t0 = Date(); _ = try Argon2id.derive(password: pw, salt: salt, params: .current)
        print(String(format: "KDF CURRENT m=%d MiB t=%d p=%d  %.3f s", KDFParameters.current.memoryKiB / 1024, KDFParameters.current.passes, KDFParameters.current.lanes, Date().timeIntervalSince(t0)))
    }
}
