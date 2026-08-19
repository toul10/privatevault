import Testing
import Foundation
@testable import VaultCore

final class FakePasteboard: Pasteboard, @unchecked Sendable {
    var contents: String? = nil
    var changeCount = 100
    var concealedWrites = 0
    func writeConcealed(_ string: String) -> Int { contents = string; changeCount += 1; concealedWrites += 1; return changeCount }
    func clear() { contents = nil; changeCount += 1 }
    /// Simulates another app copying something.
    func externalWrite(_ s: String) { contents = s; changeCount += 1 }
}
final class FakeClock: Clock, @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 1_000_000)
    private var scheduled: [(Date, () -> Void, Token)] = []
    final class Token: ClockCancellable, @unchecked Sendable { var cancelled = false; func cancel() { cancelled = true } }
    func schedule(after seconds: TimeInterval, _ body: @escaping @Sendable () -> Void) -> ClockCancellable {
        let t = Token(); scheduled.append((now.addingTimeInterval(seconds), body, t)); return t
    }
    func advance(_ seconds: TimeInterval) {
        now = now.addingTimeInterval(seconds)
        let due = scheduled.filter { $0.0 <= now }
        scheduled.removeAll { $0.0 <= now }
        for (_, body, token) in due where !token.cancelled { body() }
    }
}

@Suite("Clipboard auto-clear, auto-lock policy, password generator")
struct PolicyTests {
    @Test func clipboard_clears_after_timeout_only_if_still_ours() {
        let pb = FakePasteboard(), clock = FakeClock()
        let c = SecureClipboard(pasteboard: pb, clock: clock, timeout: 30)
        c.copy("FAKE-secret")
        #expect(pb.contents == "FAKE-secret"); #expect(pb.concealedWrites == 1); #expect(c.holdsOurSecret)
        clock.advance(29); #expect(pb.contents == "FAKE-secret")
        clock.advance(1); #expect(pb.contents == nil); #expect(!c.holdsOurSecret)
        // user copied something else in the meantime ⇒ we must not clobber it
        c.copy("FAKE-2")
        pb.externalWrite("user text")
        clock.advance(30)
        #expect(pb.contents == "user text")
        // explicit clear on lock
        c.copy("FAKE-3"); c.clearIfStillOurs(); #expect(pb.contents == nil)
        // a second copy reschedules (the first timer must not clear the second value early)
        c.copy("A"); clock.advance(20); c.copy("B"); clock.advance(15); #expect(pb.contents == "B"); clock.advance(15); #expect(pb.contents == nil)
    }

    @Test func auto_lock_idle_and_immediate_events() {
        let clock = FakeClock()
        let locked = LockFlag()
        let ctl = AutoLockController(policy: AutoLockPolicy(timeout: .oneMinute), clock: clock) { locked.set() }
        ctl.arm()
        clock.advance(30); ctl.handle(.userActivity)
        clock.advance(45); ctl.tick(); #expect(!locked.value)       // 45 s since last activity
        clock.advance(20); ctl.tick(); #expect(locked.value)        // 65 s ⇒ lock
        // immediate events
        for e in [AutoLockPolicy.Event.systemWillSleep, .screensDidSleep, .screenLocked, .sessionResignedActive, .willPowerOff, .appWillTerminate, .explicitLock] {
            locked.reset(); ctl.arm(); ctl.handle(e); #expect(locked.value, "event \(e) must lock")
        }
        // disarmed controller ignores events
        locked.reset(); ctl.disarm(); ctl.handle(.screenLocked); ctl.tick(now: clock.now.addingTimeInterval(9999)); #expect(!locked.value)
        // "never" only locks on explicit events
        let never = AutoLockController(policy: AutoLockPolicy(timeout: .never), clock: clock) { locked.set() }
        locked.reset(); never.arm(); never.tick(now: clock.now.addingTimeInterval(86400)); #expect(!locked.value)
        never.handle(.systemWillSleep); #expect(locked.value)
        // system idle time (no input anywhere on the Mac) also counts
        locked.reset(); ctl.arm(); ctl.tick(systemIdleSeconds: 61); #expect(locked.value)
        // the internal timer fires by itself
        locked.reset(); ctl.arm(); clock.advance(61); #expect(locked.value)
    }
    final class LockFlag: @unchecked Sendable { var value = false; func set() { value = true }; func reset() { value = false } }

    @Test func password_generator_respects_options_and_is_random() throws {
        let o = PasswordGenerator.Options(length: 24)
        var seen = Set<String>()
        for _ in 0..<50 {
            let p = try PasswordGenerator.generate(o)
            #expect(p.count == 24)
            #expect(p.contains { $0.isUppercase }); #expect(p.contains { $0.isLowercase }); #expect(p.contains { $0.isNumber })
            #expect(p.contains { !$0.isLetter && !$0.isNumber })
            seen.insert(p)
        }
        #expect(seen.count == 50)
        let digitsOnly = try PasswordGenerator.generate(.init(length: 8, uppercase: false, lowercase: false, digits: true, symbols: false))
        #expect(digitsOnly.allSatisfy { $0.isNumber }); #expect(digitsOnly.count == 8)
        let noAmbiguous = try PasswordGenerator.generate(.init(length: 128, excludeAmbiguous: true))
        #expect(!noAmbiguous.contains { "0Oo1lI|".contains($0) })
        #expect(throws: VaultError.self) { _ = try PasswordGenerator.generate(.init(length: 20, uppercase: false, lowercase: false, digits: false, symbols: false)) }
        #expect(PasswordGenerator.entropyBits(.init(length: 20)) > 120)
        #expect(try PasswordGenerator.generate(.init(length: 2)).count == PasswordGenerator.minLength)   // clamped
        #expect(try PasswordGenerator.generate(.init(length: 1000)).count == PasswordGenerator.maxLength)
    }

    @Test func strength_estimate_and_master_password_policy() {
        #expect(PasswordStrength.estimate("password").rating == .veryWeak)
        #expect(PasswordStrength.estimate("aaaaaaaaaaaaaaaa").rating != .strong)
        #expect(PasswordStrength.estimate("correct horse battery staple 2026").rating == .veryStrong)
        #expect(PasswordStrength.estimate("").entropyBits == 0)
        #expect(throws: VaultError.self) { try MasterPasswordPolicy.validate("short") }
        #expect(throws: VaultError.self) { try MasterPasswordPolicy.validate("passwordpassword") } // repeated common word
        #expect(throws: VaultError.self) { try MasterPasswordPolicy.validate("abcabcabcabcabcabc") }
        #expect(throws: VaultError.self) { try MasterPasswordPolicy.validate("aaaaaaaaaaaaaaaaaaaa") }
        #expect(throws: Never.self) { try MasterPasswordPolicy.validate(TestEnv.password) }
    }
}

@Suite("dotenv parser")
struct DotEnvParserTests {
    @Test func parses_common_forms() {
        let text = """
        # comment
        API_KEY=FAKE123
        export SECRET_TOKEN="FAKE with spaces"
        SINGLE='FAKE single'
        EMPTY=
        TRAILING=value # comment
        URL=https://example.com/a?b=c#frag
        bad line
        =novalue
        """
        let e = DotEnvParser.parse(text)
        #expect(e == [
            .init(key: "API_KEY", value: "FAKE123"),
            .init(key: "SECRET_TOKEN", value: "FAKE with spaces"),
            .init(key: "SINGLE", value: "FAKE single"),
            .init(key: "EMPTY", value: ""),
            .init(key: "TRAILING", value: "value"),
            .init(key: "URL", value: "https://example.com/a?b=c#frag"),
        ])
    }
}
