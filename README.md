# PrivateVault

[![CI](https://github.com/toul10/privatevault/actions/workflows/ci.yml/badge.svg)](https://github.com/toul10/privatevault/actions/workflows/ci.yml)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](LICENSE.md)

A 100% local, offline, single-user, zero-knowledge secrets manager for macOS: logins, API credentials,
secure notes, recovery codes, and crypto-wallet seed phrases / private keys in one encrypted vault file on
this Mac — and nowhere else.

> **Status: version 1.0.** The source is public so anyone can review the security design and the code.
> Signed and notarized downloads are not published yet (`RELEASING.md`). Found a security problem? Report it
> privately — see `SECURITY.md`.

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

## Your vault vs. this repository

The code is shared; every installation's data is private and separate.

- **Your vault is never in the repository.** The installed app (e.g. `/Applications/PrivateVault.app`) keeps the
  vault in its own sandbox container,
  `~/Library/Containers/com.kostastoulis.privatevault/…/Vault.noindex/vault.sqlite`, and the Secret Key in your
  Keychain. Nothing in this repository reads, writes or ships that data.
- **Development builds cannot touch it.** `Scripts/build-app.sh` builds **PrivateVault Dev**
  (`com.kostastoulis.privatevault.dev`): a separate app identity with its own empty sandbox container and its own
  Keychain items, so a test build can never open, migrate or damage the installed app's vault, nor overwrite or
  delete its Secret Key — even if you restore a copy of a real backup into it. Only `--production` builds use the
  real identity, and the script never replaces an installed app.
- **A safety net against publishing private data.** `.gitignore`, the pre-commit hook and the pre-push hook block
  vault files and backups (also when renamed), Recovery Kits, keys and signing material, `.env` files, screenshots
  and non-noreply e-mail addresses — in every file, commit message and tag that would leave the Mac, not only the
  last commit. It is a net, not a guarantee: never copy personal files into the repository folder.

## Requirements

- macOS 14 or newer.
- Apple Silicon, or an Intel Mac with a Secure Enclave (T2), recommended. Without a Secure Enclave the Secret Key
  is protected only by your login password in the Keychain; the app warns you once.
- Core library and tests: the Command Line Tools are enough (`xcode-select --install`).
- The app (SwiftUI): a current Xcode — CI uses Xcode 26.6. The Command Line Tools for Swift 6.4 ship without the
  SwiftUI macro plugin, so they can no longer compile the app; the core and its tests are unaffected.

## After cloning (one-time)

```
git config core.hooksPath .githooks     # pre-commit + pre-push secret scans in this clone
```

## Build and run

```
Scripts/build-app.sh                # → dist/PrivateVault Dev.app  (development identity, its own empty vault)
open "dist/PrivateVault Dev.app"

Scripts/build-app.sh --production   # → dist/PrivateVault.app      (real identity — releases only, RELEASING.md)
Scripts/build-app.sh --debug        # debug configuration + debug entitlements, either identity; never distribute
```

First-launch notes:
- Builds are **ad-hoc signed** (no certificate), sandboxed, with the hardened runtime. A locally built app carries
  no quarantine attribute, so Gatekeeper does not block it. Only run builds you made yourself. Never give an ad-hoc
  build to someone else — releases are Developer-ID-signed and notarized (`RELEASING.md`).
- A Dev build starts with onboarding: create a throwaway test vault with obviously fake data.
- A production build is a "new" app to macOS after every rebuild, so its first unlock shows the standard Keychain
  dialog ("PrivateVault wants to use your confidential information…"): click **Always Allow** (your login password
  may be asked). If you deny it or the item is gone, PrivateVault asks for your **Recovery Kit** once and stores the
  Secret Key again (`SECURITY_ARCHITECTURE.md` §8.1). Keep the kit at hand when you rebuild.

## Run tests

```
Scripts/run-tests.sh                                  # full Swift Testing suite (Command Line Tools or Xcode)
Scripts/run-tests.sh --filter KDF                     # a subset
Scripts/run-tests.sh -c release --filter 'Argon2|AEAD|HKDF|HPKE'   # known-answer tests in a release build
```

The script builds only the test target and the core — never the app — so it works wherever the core compiles.
Tests pin byte-level formats with known-answer vectors; OS boundaries (Keychain, Secure Enclave, Touch ID,
clipboard) are faked by default. `Scripts/secret-scan.sh --all` and `Scripts/audit-network.sh --strict` are the
other two gates. CI runs all three, plus an app build, on every push and pull request once the repository is
public (its jobs are skipped while it is private); the scan of every commit's history runs on pushes, not on pull
requests.

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
  Models/                      VaultItem, VaultFolder, Secret<T> (redacted, codec-guarded)
  Backup/  Logging/  Security/ .privatevault format, SecureLog, process hardening
Sources/PrivateVaultApp/       App/ UI/ Authentication/ Services/ — thin SwiftUI app
Tests/VaultCoreTests/          Swift Testing suite
Scripts/                       build-app.sh, run-tests.sh, secret-scan.sh, audit-network.sh, verify-bundle.sh,
                               benchmark-kdf.sh
Packaging/                     Info.plist, entitlements, icon
.githooks/                     pre-commit and pre-push secret scans
.github/                       CI workflow, issue forms, Dependabot
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
- **Folders.** Organise items in folders (e.g. *Wallets*, *Work keys*, *Exchanges*): sidebar → *Folders* → *New
  Folder…*, then pick the folder in the item editor, right-click an item → *Move to Folder*, or drag items onto a
  folder. Folder names are encrypted like everything else; deleting a folder never deletes its items.
- **Recovery rules.** Forgot the Master Password: unrecoverable. Lost the Secret Key *and* the Recovery Kit:
  unrecoverable. New Mac or reset Secure Enclave: type the Recovery Kit once. See `RECOVERY.md`.

## Document index

| File | Purpose |
|---|---|
| `SECURITY_ARCHITECTURE.md` | Normative crypto and storage specification |
| `THREAT_MODEL.md` | Attacker scenarios; what is defended and what is not |
| `RECOVERY.md` | Loss scenarios and what is recoverable |
| `SECURITY_AUDIT.md` | Self-audit checklist and findings |
| `DEPENDENCY_SECURITY.md` | Vendored code, pinning, supply chain, CI |
| `FUTURE_SYNC_ARCHITECTURE.md` | Plan for a later zero-knowledge sync (not built) |
| `SECURITY.md` | How to report a vulnerability privately |
| `PRIVACY.md` | Privacy policy: the app collects nothing |
| `RELEASING.md` | Developer ID signing, notarization, publishing a release |
| `CONTRIBUTING.md` | How to help; why pull requests are not accepted yet |
| `CHANGELOG.md` | Release history |
| `Sources/CArgon2/VENDOR.md` | Argon2 provenance and per-file hashes |

## License

PrivateVault is **source-available** under the [Functional Source License, Version 1.1, ALv2 Future
License](LICENSE.md) (FSL-1.1-ALv2). In plain words:

- You may read, audit, build, modify and use it — personally, inside your company, for research and education.
- You may not use it to offer a competing commercial product or service.
- Each released version automatically becomes available under the Apache License 2.0 two years after its release.

The vendored Argon2 code keeps its own license, CC0 1.0 / Apache 2.0 (`Sources/CArgon2/LICENSE`).
"PrivateVault" and the app icon are not licensed for use by other products.

## No warranty

PrivateVault is provided "as is", without warranty of any kind (see `LICENSE.md`). By design there is no
backdoor: if you lose your Master Password, or both your Secret Key and your Recovery Kit, your data cannot be
recovered by anyone. Keep encrypted backups and your printed Recovery Kit.
