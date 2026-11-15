# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-15

First public source release.

### Vault
- Local-only, single-user encrypted vault for logins, API credentials, secure notes, recovery codes and
  crypto-wallet seed phrases / private keys.
- Key hierarchy: Master Password (Argon2id, 256 MiB · t=6 · p=4) and a 256-bit Secret Key (Secure-Enclave-wrapped
  in the Keychain, printed Recovery Kit) → KEK → Vault Master Key; AES-256-GCM records under HKDF-derived keys.
- All record metadata encrypted, records padded to 4 KiB; a keyed state MAC detects deleted, spliced and
  rolled-back records; per-record quarantine instead of failing the whole vault.
- Seed phrases and private keys in an inner encrypted box, revealed only after Touch ID or the login password.
- Folders with encrypted names: create, rename, delete (never deletes items), Move to Folder, drag & drop.
- Import `.env` files (one API Credential per key, or one Secure Note).
- Password generator and strength estimate.
- Encrypted `.privatevault` backups; restore needs Master Password + Secret Key.
- Change Master Password (re-wrap) with optional full key rotation; Secret Key regeneration.

### Protection
- No network entitlement — the sandbox blocks every socket; no telemetry, no update checks.
- Touch ID unlock bound to the Secure Enclave; Touch ID gate for revealing and copying secrets (30 s grace).
- Auto-lock on idle, sleep and quit, wiping keys; clipboard cleared after 30 s, local-only and concealed.
- Unlock throttling; KDF parameters can only go up; header checksum and header-bound Touch ID.
- Hardened runtime, App Sandbox, no window restoration, no core dumps.

### Project
- Swift Testing suite with known-answer vectors and a frozen golden v1 vault and backup fixture.
- `Scripts/run-tests.sh` builds only the core and its tests, so the suite runs with the Command Line Tools.
- Development builds use their own identity ("PrivateVault Dev"), sandbox container and Keychain items, so they
  can never open an installed vault or overwrite its Secret Key.
- Pre-commit and pre-push secret scans: vault files and backups (also renamed), keys and signing material,
  Recovery Kits in any form, `.env` files, screenshots and private e-mail addresses — in every pushed file, commit
  message and tag; CI on GitHub Actions.
- Licensed under FSL-1.1-ALv2.

[1.0.0]: https://github.com/toul10/privatevault/releases/tag/v1.0.0
