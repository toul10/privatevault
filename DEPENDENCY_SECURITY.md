# PrivateVault — Dependency Security (Version 1)

Companion to `SECURITY_ARCHITECTURE.md` (normative) and `THREAT_MODEL.md`. This document lists every piece of
code PrivateVault runs that we did not write ourselves, why it is there, how it is pinned, and how it is re-checked.

## 0. Policy in three sentences

PrivateVault has **zero remote Swift Package Manager dependencies**: `Package.swift` has no package-level
`dependencies:` array, no `.package(…)` entry, and there is no `Package.resolved`. The only third-party code is one
vendored C library (the PHC reference Argon2), copied into the repository and pinned by SHA-256; everything else is
Apple platform code that ships with macOS, plus our own small targets. There are no analytics, crash-reporting,
update or telemetry SDKs, and the app has no network entitlement, so nothing could phone home even by accident.

## 1. Inventory

| Component | Kind | Used for | Trust basis |
|---|---|---|---|
| `Sources/CArgon2` | Vendored C (third-party) | Argon2id password stretching (§2.3 of the architecture) | Pinned upstream tag, per-file SHA-256, known-answer tests |
| Apple CryptoKit | Platform framework | AES-256-GCM, HKDF-SHA256, HPKE, HMAC-SHA256, SHA-256, Secure Enclave keys | Apple, corecrypto underneath |
| System SQLite (`libsqlite3`) | Platform library | Vault file storage | Apple-built, updated with macOS |
| Security.framework, LocalAuthentication, AppKit, SwiftUI, Foundation, OSLog | Platform frameworks | Keychain, access control, CSPRNG, Touch ID, UI, pasteboard, logging | Apple |
| `Sources/CSecureMemory` | Our own C shim | `memset_s`, `timingsafe_bcmp`, `mlock`/`munlock` | Our code (24 lines), wraps Darwin libc |
| Swift Testing | Toolchain framework | Tests only | Apple toolchain; never linked into the app |

## 2. CArgon2 — vendored PHC reference Argon2

**Why it exists.** CryptoKit offers no password-hashing function (no Argon2, no scrypt, no PBKDF2 in the public
API). Argon2id is the algorithm the architecture requires, so it has to come from outside Apple's frameworks.

**Why the PHC reference and not something else.**
- It is the canonical implementation by the Argon2 authors, the reference for RFC 9106, about 3.3k lines of plain
  C in 13 files — small enough to read end to end.
- Its context API (`argon2_ctx`) supports lanes `p > 1` (the header allows `p ∈ [1, 4]`) and reproduces the
  RFC 9106 §5.3 known-answer vector (which needs secret and associated-data inputs). The test suite pins that vector
  plus four OpenSSL-derived `p = 1` vectors; OpenSSL 3.6.3 on this Mac is the independent oracle.
- **libsodium** was rejected: `crypto_pwhash` fixes `p = 1`, a 16-byte salt and no secret/AD inputs (cannot run
  the RFC vector), and its tree expects autotools-generated headers — vendoring ~100k lines for one primitive
  enlarges the trusted code base for no gain.
- **CryptoSwift** (and similar Swift packages) was rejected: not audit-grade, no Argon2, and it would be a remote
  SwiftPM dependency, which the policy forbids.

**Pinning and verification.** `Sources/CArgon2/VENDOR.md` records upstream
`https://github.com/P-H-C/phc-winner-argon2`, release tag `20190702`, tarball
`phc-winner-argon2-20190702.tar.gz` with SHA-256
`daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c` (cross-checked against the Homebrew `argon2`
formula checksum and `shasum` on 2026-08-19), the license (CC0 1.0 / Apache 2.0) and a SHA-256 for each of the
14 files (13 sources + `LICENSE`), copied unmodified from upstream `src/`, `src/blake2/` and `include/`.
To verify the tree at any time:

```
cd Sources/CArgon2 && grep '^- `' VENDOR.md | sed -E 's/^- `(.*)` ([0-9a-f]{64})$/\2  \1/' | shasum -a 256 -c -
```

**Build.** Plain SwiftPM C target, `cSettings: headerSearchPath("."), unsafeFlags(["-O2"])` (allowed for the
root package). `ref.c` is the portable implementation and is what runs on Apple silicon; `thread.c` is included so
`p > 1` works via pthreads. The Swift wrapper in `VaultCore` calls the context API with type Argon2id, version
`0x13`, and flags `ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET`, so the library wipes the password buffer
it was given (we pass no secret). The reference already wipes its own working memory with `memset_s` on macOS
(`clear_internal_memory`, on by default).

**What we deliberately do not use.** `opt.c` (x86 SSE/AVX intrinsics — not vendored), `bench.c`, `genkat.c`,
`run.c`, `test.c`, the command-line tool, and the `$argon2id$…` encoded-string API (we store raw 32-byte outputs).

**Maintenance status — honestly.** The algorithm is finalised (RFC 9106, 2021) and the reference is complete, so
upstream commit activity is low and the last release tag is from 2019. That is expected, not a warning sign, but it
means we must look for problems ourselves: no published CVE against the reference was known at vendoring time, and
that must be re-verified before each release, never assumed. Where to look: the upstream GitHub repository (Issues,
Releases, Security tab), an NVD/CVE search for "argon2" / "phc-winner-argon2", the Homebrew `argon2` formula
(bumps track upstream), and the libsodium changelog (it carries a derivative of the same code).

## 3. Apple CryptoKit

All AEAD, KDF, MAC, hashing, HPKE and Secure Enclave key operations go through CryptoKit exactly as listed in §1 of
`SECURITY_ARCHITECTURE.md`. CryptoKit is a thin Swift API over Apple's **corecrypto**, whose modules Apple submits
for FIPS 140-3 validation (the validated boundary is corecrypto, not CryptoKit itself). It ships with macOS, is
patched by Apple security releases, and is hardware-accelerated on Apple silicon. The package declares
`platforms: [.macOS(.v14)]` because HPKE with `SecureEnclave.P256.KeyAgreement.PrivateKey` needs macOS 14. We never
implement a primitive ourselves and never call corecrypto or CommonCrypto directly.

## 4. System SQLite

`VaultCore` links the macOS `libsqlite3` (SDK 3.51.0 on macOS 26.5) and uses the C API directly with the hardening
settings of §5.1 of the architecture (`NOFOLLOW | EXRESCODE`, `SQLITE_DBCONFIG_DEFENSIVE`, `secure_delete`,
`integrity_check`). We do **not** use GRDB or SQLCipher: every record is encrypted with AES-256-GCM before it
reaches SQLite, so the database only ever holds ciphertext and non-secret parameters. Whole-file encryption would
add nothing to confidentiality, would introduce a second key to manage, and both would be remote dependencies
(SQLCipher also brings its own crypto library). Apple updates SQLite with the OS; we inherit fixes without re-vendoring.

## 5. Security.framework, LocalAuthentication, AppKit, SwiftUI

Platform frameworks, used only through public APIs: `SecItem*`/`SecAccessControl*` (Keychain, Secure Enclave
access policies), `SecRandomCopyBytes`/`SystemRandomNumberGenerator` (randomness), `LAContext` (Touch ID,
authentication gates), `NSPasteboard`/`NSWindow` (clipboard hygiene, window-sharing control), `SecureField`
(Secure Event Input). Nothing here is vendored or wrapped by third-party code.

## 6. CSecureMemory

Our own 24-line C file plus header in `Sources/CSecureMemory`, exposing `pv_memzero` (`memset_s`), `pv_ct_equal`
(`timingsafe_bcmp`), `pv_mlock`/`pv_munlock` to Swift. Not a dependency: it contains no logic of its own and is
audited by reading it. It exists because Swift cannot reliably call these libc functions without a C shim.

## 7. Swift Testing

Provided by the Swift toolchain (`Testing.framework` from the Command Line Tools; no Xcode, no XCTest on this
machine). Linked only into `VaultCoreTests` via `Scripts/run-tests.sh`; never part of the app bundle.

## 8. Re-vendoring Argon2 (update procedure)

1. Read the upstream diff between `20190702` and the new tag/commit; decide whether it is needed.
2. Download the release tarball; `shasum -a 256` it; compare with the Homebrew formula checksum (`brew cat argon2`)
   or the GitHub release page. Two independent sources must agree.
3. Copy the **same 13 source files + LICENSE** (listed in `VENDOR.md`) from `src/`, `src/blake2/`, `include/`.
   Do not add `opt.c`, `bench.c`, `genkat.c`, `run.c`, `test.c`.
4. Recompute every per-file SHA-256 and rewrite `VENDOR.md` (tag, tarball hash, date, file list).
5. `swift build -c release`, then `Scripts/run-tests.sh`: the RFC 9106 §5.3 vector and the OpenSSL-derived vectors
   must pass byte-for-byte; `KDFParameters.current ≥ floor` must still hold.
6. Re-run `Scripts/benchmark-kdf.sh` if performance changed; never lower parameters.
7. Commit with the upstream tag in the message; note the change in `SECURITY_AUDIT.md`.

## 9. What to re-check before each release

- `grep -c '\.package(' Package.swift` prints `0`; no `Package.resolved`; no package-level `dependencies:`.
- The `VENDOR.md` hash check (§2) prints `OK` for all 14 files.
- Upstream Argon2 advisories (sources in §2) searched; result recorded in `SECURITY_AUDIT.md`.
- `grep -rh '^import ' Sources Tests | sort -u` lists only Apple frameworks, `CArgon2`, `CSecureMemory`,
  `VaultCore` and (tests only) `Testing`.
- Built app: `codesign -d --entitlements - --verbose` shows exactly `app-sandbox` and
  `files.user-selected.read-write`, hardened runtime on, no network entitlement; `otool -L` lists only system
  libraries and frameworks.
- `Scripts/secret-scan.sh --all` passes.
- Current macOS security release notes reviewed for CryptoKit/corecrypto, SQLite and Security.framework fixes — we
  inherit them by updating the OS, not by re-vendoring.
- All Argon2, HKDF, AES-GCM and HPKE known-answer tests green in a **release** build.
