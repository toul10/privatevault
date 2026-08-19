# PrivateVault

A 100% local, offline, single-user, zero-knowledge secrets manager for macOS: logins, API credentials,
secure notes, recovery codes, and crypto-wallet seed phrases / private keys in one encrypted vault file on
this Mac — and nowhere else.

## What PrivateVault is — and is not

**Is (Version 1):** a native macOS app (Swift, SwiftUI, CryptoKit). The vault lives in the app's sandbox
container, unlocks with your Master Password (or Touch ID once enabled), and exports encrypted `.privatevault`
backups.

**Is not (Version 1):**
- **No network.** No network entitlement, so the kernel blocks every socket. No telemetry, no update check.
- **No sync server yet.** `FUTURE_SYNC_ARCHITECTURE.md` is a plan; nothing of it is built.
- **No blockchain features.** Wallet items hold seed phrases, private keys, addresses and derivation paths as
  text. No signing, no RPC, no key derivation, no balances.
- **No plaintext export.** Backups contain only ciphertext.
- **No developer key, no universal recovery key.** Lose both the Master Password and the Recovery Kit and
  nobody — including the author — can open the vault.

## Security model in 10 lines

1. Every secret is encrypted with AES-256-GCM under keys derived (HKDF-SHA256) from a random Vault Master Key (VMK).
2. The VMK is stored only wrapped by a Key Encryption Key (KEK).
3. The KEK needs **two** secrets: your Master Password (stretched with Argon2id) **and** a random 256-bit Secret Key.
4. The Secret Key lives outside the vault file: Secure-Enclave-wrapped in the macOS Keychain and on paper in your Recovery Kit.
5. So a stolen vault file, backup or Time Machine copy cannot even *start* a password-guessing attack.
6. Inside each record everything is ciphertext — type, title, username, timestamps; only a random id, a format-version number, a revision counter and a padded size are visible.
7. Seed phrases and private keys sit in an inner encrypted box, opened only on **Reveal** after Touch ID / login password.
8. A keyed state MAC detects deleted or rolled-back records; backups are authenticated (but not "fresh").
9. Touch ID is a convenience unlock enforced by the Secure Enclave; it never stores your password.
10. Honest limit: malware or a person using this Mac **while the vault is unlocked** can read what you can read.

Details: `SECURITY_ARCHITECTURE.md` (normative spec), `THREAT_MODEL.md` (what is and is not defended),
`RECOVERY.md` (which loss scenarios are recoverable).

## Requirements

- macOS 14 or newer.
- Apple Silicon, or an Intel Mac with a Secure Enclave (T2), recommended. Without a Secure Enclave the Secret Key
  is protected only by your login password in the Keychain; the app warns you once.
- To build: only the Command Line Tools (`xcode-select --install`). No Xcode, no Apple Developer account.

## Build and run

```
Scripts/build-app.sh        # → dist/PrivateVault.app
open dist/PrivateVault.app
```

First-launch notes:
- The app is **ad-hoc signed** (no certificate), sandboxed, with the hardened runtime. A locally built app carries no
  quarantine attribute, so Gatekeeper does not block it. Only run builds you made yourself.
- After a rebuild macOS sees a "new" app, so the first unlock shows the standard macOS Keychain dialog
  ("PrivateVault wants to use your confidential information…"): click **Always Allow** (your login password may be
  asked). If you deny it or the item is gone, PrivateVault asks for your **Recovery Kit** once and stores the Secret
  Key again (`SECURITY_ARCHITECTURE.md` §8.1). Keep the kit at hand when you rebuild.
- Nothing is installed system-wide; the vault is
  `~/Library/Containers/com.kostastoulis.privatevault/…/Vault.noindex/vault.sqlite`.

## Run tests

```
Scripts/run-tests.sh                 # Swift Testing under Command Line Tools
Scripts/run-tests.sh --filter KDF    # a subset
```

Tests pin byte-level formats with known-answer vectors; OS boundaries (Keychain, Secure Enclave, Touch ID,
clipboard) are faked by default.

## Project layout

```
Package.swift                  SwiftPM manifest (macOS 14+, Swift 6)
Sources/CArgon2/               vendored PHC reference Argon2id (pinned, hash-verified) — the only third-party code
Sources/CSecureMemory/         memset_s / timingsafe_bcmp / mlock shim
Sources/VaultCore/             all security logic, no UI
  Crypto/                      key hierarchy, Argon2id, HKDF labels, AES-GCM record envelope, canonical header,
                               HPKE wrap, SecureBytes, Recovery Kit
  Keychain/  SecureEnclave/    Secret Key and Touch ID blobs (HPKE to Secure Enclave keys)
  Vault/  Database/            unlock, rotation, SQLite store, state MAC
  Models/                      VaultItem, Secret<T> (redacted, codec-guarded)
  Backup/  Logging/  Security/ .privatevault format, SecureLog, process hardening
Sources/PrivateVaultApp/       App/ UI/ Authentication/ Services/ — thin SwiftUI app
Tests/VaultCoreTests/          Swift Testing suite
Scripts/                       build-app.sh, run-tests.sh, benchmark-kdf.sh, secret-scan.sh
Packaging/                     Info.plist, entitlements
docs, *.md                     see Document index
```

## Daily use

- **Create the vault.** Master Password of at least 12 characters (the app estimates ≥ 50 bits). It is the only
  barrier if someone also gets your Secret Key. Leading/trailing spaces count.
- **Print the Recovery Kit.** `PV1-XXXXX-…` (11 groups) is shown once; you re-type one group to continue. Keep it
  on paper in a safe place, never as a photo or cloud file — it is as sensitive as the vault.
- **Enable Touch ID** (while unlocked). Adding or removing a fingerprint disables it; re-enable afterwards.
- **Make encrypted backups** (requires the Master Password). Restoring needs Master Password + Secret Key. An old
  backup still opens with the *old* password unless you rotated keys — delete old backups if that matters.
- **Auto-lock.** Locks after the idle timeout and via *Lock Now*; locking wipes all keys from memory and clears
  the clipboard (the clipboard is also cleared on sleep and on quit).
- **Clipboard.** Copies are local-only (no Universal Clipboard), marked concealed, cleared after 30 s by default.
  A clipboard manager that ignores the markers can still capture them.
- **Wallet secrets.** Seed phrases and private keys stay encrypted even while unlocked. *Reveal* asks for Touch ID
  or your login password, shows a warning, and hides again after 30 s.
- **Recovery rules.** Forgot the Master Password: unrecoverable. Lost the Secret Key *and* the Recovery Kit:
  unrecoverable. New Mac or reset Secure Enclave: type the Recovery Kit once. See `RECOVERY.md`.

## Document index

| File | Purpose |
|---|---|
| `SECURITY_ARCHITECTURE.md` | Normative crypto and storage specification |
| `THREAT_MODEL.md` | Attacker scenarios; what is defended and what is not |
| `RECOVERY.md` | Loss scenarios and what is recoverable |
| `FUTURE_SYNC_ARCHITECTURE.md` | Plan for a later zero-knowledge sync (not built) |
| `DEPENDENCY_SECURITY.md` | Vendored code, pinning, supply chain |
| `SECURITY_AUDIT.md` | Self-audit checklist and findings |
| `Sources/CArgon2/VENDOR.md` | Argon2 provenance and per-file hashes |

## License

To be decided by the owner. Vendored Argon2 is CC0 1.0 / Apache 2.0 (`Sources/CArgon2/LICENSE`).
