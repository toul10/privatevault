# PrivateVault — Threat Model (Version 1)

Plain language first, precise details second: **what PrivateVault defends against, what it does not, and why**.
Companion of `SECURITY_ARCHITECTURE.md` (the normative spec; `§n` refers to its sections). Version 1 is 100 % local,
offline and single-user: no network, no telemetry, no sync server, no plaintext export, no developer key, no
universal recovery key.

---

## 1. Assets (what we are protecting)

| Tier | Asset | Where it lives / how it is protected |
|---|---|---|
| **Root key material** | Master Password (MP), Secret Key (SK), Recovery Kit, VMK / KEK / subkeys | MP: user's memory only, never stored. SK: Secure-Enclave-wrapped in the Keychain + on paper (§2.4, §8.1). VMK and subkeys: process memory only while unlocked, in `SecureBytes` / `SymmetricKey` (§7.5, §10). |
| **Tier 2** | Wallet seed phrases, wallet private keys | Inner AEAD box under `tier2Key` (AAD `"tier2" ‖ vaultID ‖ recordID ‖ fieldName`) *inside* the encrypted record (§4.4). Stays ciphertext in memory until **Reveal**, which needs system authentication and auto-hides after 30 s (§8.3). |
| **Tier 1** | Login passwords, API keys/secrets, recovery codes, secure-note bodies, wallet notes / derivation path | Record envelope: AES-256-GCM under a per-record key derived from `recordRootKey` (§4.2). In memory only while unlocked. |
| **Encrypted metadata** | Item type, title, website, username, tags, favourite, timestamps, public addresses, blockchain | Inside the same ciphertext; padded to size buckets (§4.1, §4.3). A file thief cannot tell a wallet from a login. |
| **Visible metadata** (accepted leak) | Record count, random record ids, `crypto_version`, revision counters, padded size class, vault UUID, *vault* creation time (record timestamps are encrypted), format version, generation, KDF parameters + salt, `sk_id`, `header_sha256`, `state_mac`, `wrapped_VMK` (ciphertext) | Plaintext by design; none of it helps decrypt anything (§11). |

Tier 2 is a *handling* distinction (shorter plaintext lifetime, extra gate), not a separate trust boundary:
`tier2Key` is derived from the VMK like every other subkey (§4.4).

---

## 2. Trust assumptions

PrivateVault's guarantees hold **only if**:

- **macOS is honest** — kernel, App Sandbox, Keychain, TCC, Secure Event Input, encrypted swap, the OS CSPRNG.
- **The Secure Enclave** keeps its P-256 keys inside the SEP and enforces `.biometryCurrentSet` for the Touch ID key.
  Honest limit: the SK-wrapping key uses `[.privateKeyUsage]` only, so it gives **off-device** protection — any process
  on *this* Mac that obtains the blob can ask this Mac's SEP to use it (§8.1, scenario 3.6).
- **CryptoKit / corecrypto** and the vendored PHC Argon2id reference (`Sources/CArgon2`, pinned, hash-verified) are
  correct and constant-time.
- **The login password is strong and FileVault is on.** The classic login keychain (which an ad-hoc build must use,
  §8.1 item 3) is encrypted under the login password; the disk is protected at rest only by FileVault.
- **The Mac is not compromised while the vault is unlocked** — no malware, keylogger, remote-control or screen recorder
  in the user's session.
- **The user** memorises the MP and keeps the Recovery Kit on paper, never photographed or uploaded.
- **The app bundle is ours.** Ad-hoc signatures carry no certificate chain (§10); macOS cannot prove it was not swapped.

---

## 3. Attacker scenarios

Same four lines everywhere: **Gets** (what the attacker obtains) · **Stopped by** · **Residual** (honest remaining
risk) · **Mechanism** (the concrete control in the spec).

### 3.1 Thief copies `vault.sqlite` only

- **Gets**: canonical header (format version, vault UUID, Argon2id parameters, salt, generation, vault creation time),
  `wrapped_VMK` (92 bytes: nonce ‖ ciphertext ‖ tag), `header_sha256`, `sk_id`, `state_mac`, each record's random id,
  revision, crypto_version and padded ciphertext; maybe old ciphertext in free pages, the rollback journal, APFS
  snapshots or Time Machine (§5.1).
- **Stopped by**: the KEK needs **both** MPK and SKK. Without the 256-bit SK there is no candidate KEK and therefore
  *nothing to test a password guess against* — offline cracking cannot even start, however weak the MP is.
- **Residual**: the visible metadata of §1, plus — from old ciphertext blocks — the fact *that* a record changed
  (never what changed, §5.1). Nothing else.
- **Mechanism**: `KEK = HKDF(MPK ‖ SKK)`; VMK wrapped under KEK with the header as AAD (§2, §3.2); per-record keys and
  padding (§4.2, §4.3); no stored verifier of MP or SK (§3.2).

### 3.2 Thief copies the whole app container

- **Gets**: 3.1 plus the container's Preferences plist, Caches and Saved Application State.
- **Stopped by**: the SK is **not** in the container (the Keychain lives outside it); `UserDefaults` holds only
  non-sensitive settings; window restoration and `@SceneStorage` disabled; no Spotlight index; no plaintext temp files
  (§9, §10); `Secret<T>` refuses any encoder other than the record codec (§6).
- **Residual**: identical to 3.1. Required check: a test that exercises every flow with sentinel secrets and then
  searches the whole container (Preferences, Saved Application State, Caches, the vault file) for them.
- **Mechanism**: SK storage rules (§8.1 items 1–4); `Secret<T>` codec guard; "no leaks to disk" list (§10).

### 3.3 Thief gets a Time Machine backup (including the login keychain)

- **Gets**: 3.2 plus `~/Library/Keychains/login.keychain-db`, encrypted only under the **login password** and crackable
  offline with GPUs. Inside: the SE-wrapped SK record `{version, seKeyDataRepresentation, encapsulatedKey, ciphertext}`,
  the Touch ID blob, the non-secret generation / `header_sha256` mirror.
- **Stopped by**: both blobs are HPKE ciphertexts whose private keys exist only inside *this Mac's* Secure Enclave
  (`seKeyDataRepresentation` is itself SEP-encrypted). Elsewhere they are useless: this collapses to 3.1.
- **Residual**: (a) **No Secure Enclave** (VM, old Intel Mac): SK is stored raw in the login keychain (§8.1 item 2), so a
  cracked login password yields SK → scenario 3.12 (MP-only guessing). The app shows a one-time warning in that case.
  (b) Headers/backups captured *before* a password change stay openable with the old MP + SK unless keys were rotated
  (§7.3, §7.4).
- **Mechanism**: HPKE `P256_SHA256_AES_GCM_256`, `info = "privatevault/v1/hpke/se-wrap-sk" ‖ vaultID`, `aad = 0x01 ‖
  vaultID`; SE key `[.privateKeyUsage]`; `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; `kSecAttrSynchronizable = false`
  (§8.1, §8.2).

### 3.4 Thief gets a `.privatevault` backup

- **Gets**: the JSON: header (canonical, `wrappedVMK`, `headerSHA256`, `skID`), all record envelopes, the encrypted
  manifest, `createdAt` (§9).
- **Stopped by**: the file never contains SK, MP, any plaintext field or title; restore needs **MP + SK** (typed from the
  Recovery Kit when the Keychain lacks it). Equivalent to 3.1.
- **Residual**: backup creation time and record count. A backup made before a key rotation stays openable with the
  credentials of that time (§7.4) — delete old backups after rotating.
- **Mechanism**: §9 contents rule; manifest `AES-256-GCM(backupManifestKey, aad = "backup" ‖ version ‖ vaultID ‖
  createdAt)`; size and record-count bounds checked before parsing.

### 3.5 Compromised FUTURE sync server (not built in V1)

- **Gets**: what a backup contains, plus traffic metadata (which records changed when, sizes, device keys).
- **Stopped by**: no VMK and no SK ever leave the user's devices; the server can neither decrypt nor test MP guesses.
- **Residual**: a hostile server can **withhold, fork, replay or drop** updates per device or serve an older legitimate
  state; a revoked device keeps the VMK until keys rotate. Per-device freshness and enrolment verification are not in
  V1 — see `FUTURE_SYNC_ARCHITECTURE.md`.
- **Mechanism laid down in V1**: `revision` in record AAD, `generation` in header AAD, `state_mac`, `crypto_version`, key
  rotation (§7.4), frozen canonical encodings, reserved label `privatevault/v1/sync-auth` (§2).

### 3.6 Temporary physical access to an UNLOCKED Mac, vault LOCKED

- **Gets**: the ability to run code as the user; a copy of the container (= 3.1); the locked UI.
- **Stopped by**: unlocking needs the MP (Argon2id) or the owner's finger — Touch ID is enforced by the SEP, and enrolling
  a finger needs the login password. The Keychain item's ACL is bound to the app; any other process asking for it gets
  a prompt demanding the **login password**. Hardened runtime blocks debugger attach and library injection. Automatic
  lock (idle, sleep, screen lock) shortens the window; §7.5 defines what Lock drops.
- **Residual**: an attacker who **knows the login password** can read the SE-wrapped SK and, because that SE key has no
  user-presence requirement, let *this Mac's* SEP unwrap it → SK → scenario 3.12 (MP guessing at Argon2id cost). They
  can also swap the ad-hoc-signed bundle for a trojan that captures the next MP (section 4 below, spec §10).
- **Mechanism**: MP + SK KEK; `[.biometryCurrentSet]` Touch ID key; app-bound Keychain item ACL (no silent read by other
  builds/processes); hardened runtime without `get-task-allow`; Lock (§7.5, §8.1, §8.2, §10).

### 3.7 Physical access with the vault UNLOCKED

- **Gets**: every tier-1 value the UI shows or copies; the ability to edit or delete records; an exported backup
  (ciphertext only).
- **Stopped by**: **policy gates** — Reveal/copy of seed phrases and private keys needs `LAContext
  .deviceOwnerAuthentication` (Touch ID or login password) plus a warning, auto-hidden after 30 s; showing the Recovery
  Kit, changing the password, rotating keys, regenerating the SK, disabling Touch ID, exporting a backup and deleting
  the vault need the MP again (§8.3). Auto-lock; `accessibilityProtectedContent` on revealed views; window sharing
  blocked while unlocked (§10).
- **Residual**: tier-1 secrets on screen are lost; the tier-2 gate is void if the attacker knows the login password;
  edits/deletions are invisible to `state_mac` because the app recomputes it (§5.3). The gates are enforced by code
  that already holds the keys — **not** a cryptographic boundary (§8.3).
- **Mechanism**: §8.3 gate table; §4.4 tier-2 boxes; §7.5 Lock.

### 3.8 Clipboard history / Universal Clipboard

- **Gets**: whatever the user copies, while it sits on the pasteboard.
- **Stopped by**: `NSPasteboard.prepareForNewContents(with: .currentHostOnly)` (no Handoff / Universal Clipboard);
  `org.nspasteboard.ConcealedType` + `TransientType` markers; clear after the configured timeout (default 30 s), on lock,
  quit and sleep — only if the change count shows our item is still there. The app never reads the pasteboard (§10).
- **Residual**: a clipboard manager that ignores the markers, or any pasteboard poller, captures the value instantly;
  macOS offers no API to prevent it. Prefer Reveal-and-type for tier-2 values.
- **Mechanism**: §10 "Clipboard".

### 3.9 Logs, crash reports, swap, core dumps

- **Gets**: unified log entries, `.ips` crash reports, swap pages, core files.
- **Stopped by**: `SecureLog` accepts only `StaticString` messages and non-secret typed values — a `String` cannot be
  logged; assertions never interpolate values; `RLIMIT_CORE = 0`; macOS swap is encrypted; a test asserts sentinel
  secrets never appear in `OSLogStore` (§10).
- **Residual**: a crash report holds register/stack snippets; Swift `String`/`Data` copies used by the UI cannot all be
  zeroised (section 4 below, spec §10). Keys themselves live in `SecureBytes` (`mlock` + `memset_s`) or CryptoKit
  `SymmetricKey`.
- **Mechanism**: §10 "Logging", "Crash reports", "Memory wiping".

### 3.10 Tampering: records, header, backup, rollback, record swap, KDF downgrade

| Attack | Detected / prevented by |
|---|---|
| Edit or truncate a record blob (nonce, ciphertext, tag) | AES-GCM tag → `VaultError.authenticationFailed` for that record (§4.2) |
| Swap blobs between two record ids; move a record to another vault | `recordID` and `vaultID` in the AAD `"record" ‖ vaultID ‖ recordID ‖ crypto_version ‖ revision` (§4.2) |
| Restore an older *authentic* version of one record | `revision` in AAD + `state_mac` mismatch → warning "vault modified outside PrivateVault or rolled back" (§5.3) |
| Delete or add rows outside the app | `state_mac` covers count and the sorted (id, revision) list, rewritten in the same transaction as every write (§5.3) |
| Roll back the whole `vault.sqlite` to an older copy | Keychain mirror of last seen `generation` + `header_sha256`; lower generation → whole-file-rollback warning (a real Time Machine restore can be acknowledged) (§5.3) |
| Modify the header; **downgrade Argon2id parameters**; change salt, vaultID, pw_norm, wrap_alg | The canonical header is the **AAD of `wrapped_VMK`** → unwrap fails closed with the same `authenticationFailed`; parameters are bounds-checked *before* any allocation (§2.3, §3.1, §3.2). `header_sha256` is UX only |
| Replay an old authentic header (e.g. pre-password-change) | `generation` is in the canonical bytes and mirrored in the Keychain → warning. Honest limit: with the **old MP + SK** that header still opens the unchanged VMK unless keys were rotated (§7.3, §7.4) |
| Backup: splice header of backup A with records of backup B; drop/add/roll back a record; alter `createdAt` | Encrypted manifest binds `header_sha256`, the exact record set with per-blob SHA-256, and `createdAt` in the AAD (§9) |
| Backup: substitute an entire older legitimate backup | **Not detectable** — backups are authenticated, not fresh; the user sees `createdAt` (§9) |

**Limit**: `state_mac` is keyed from the VMK, so anyone who can *unlock* the vault can recompute it; it detects tampering
by someone who cannot decrypt, which is the at-rest threat model (§5.3).

### 3.11 Millions of offline guesses against the Master Password

- **Gets**: a vault or backup copy and unlimited compute.
- **Stopped by**: **without SK** — impossible to start (3.1). **With SK** (3.12) — each guess costs one Argon2id run
  with `m ≥ 64 MiB, t ≥ 3` (production parameters tuned to 0.5–1.0 s on this Mac, never lowered, §2.3); new vaults
  require ≥ 12 characters and an estimated ≥ 50 bits of entropy (§2.2). At 10,000 guesses per second (a large
  memory-hard rig) half of a 50-bit space takes roughly 1,800 years.
- **Residual**: a weak or reused MP combined with a leaked SK. Headers below `KDFParameters.current` are upgraded on the
  next password unlock, never on the Touch ID path (§2.3).
- **Mechanism**: Argon2id + parameter floor + untrusted-parameter bounds (§2.3); the key-committing wrap (§3.2) gives no
  cheaper oracle than a full KDF run.

### 3.12 Secret Key leaked (photo of the Recovery Kit)

- **Gets**: SK → SKK. Combined with any copy from 3.1–3.4 the vault becomes **MP-only**; `sk_id` tells them which vault.
- **Stopped by**: the Master Password — now the *only* barrier, at Argon2id cost per guess (3.11).
- **Residual**: a weak or observed MP means the vault is lost. **Remedy**: "Regenerate Secret Key" forces a key
  rotation — new SK, new VMK, every record re-encrypted, new header, old Touch ID blob replaced (re-wrapped under the
  new VMK, §7.4), `VACUUM`. The photographed kit and all *old* headers/backups then no longer decrypt current
  records; backups made *before* the rotation still open with old MP + old SK and must be deleted by the user.
- **Mechanism**: §2.1 "Why two secrets"; §2.2 password policy; §7.4 rotation; §2.4 kit format.

---

## 4. Explicitly out of scope / honest limitations

- **Malware in the logged-in session** while the vault is unlocked: reads process memory, calls the SEP with our
  blobs, watches the UI. Nothing in PrivateVault survives this.
- **Keyloggers**: `SecureField` enables Secure Event Input for the MP; kernel-level or TCC-approved input monitoring
  is outside our control.
- **Memory reading while unlocked**: VMK, subkeys and decrypted tier-1 values are in RAM; tier-2 stays boxed until
  Reveal to shorten the window, not to close it (§4.4, §10).
- **Screen capture / screen sharing / Accessibility API abuse**: `NSWindow.sharingType = .none` (default on) and
  `accessibilityProtectedContent` reduce exposure; a process granted Screen Recording or Accessibility still reads
  what is shown.
- **A trojaned app bundle**: the ad-hoc signature has no certificate chain; anyone who can write to wherever the bundle
  lives (`dist/`, `/Applications`, …) can replace it and capture the next MP (§10).
- **Weak login password + no FileVault**: the login keychain and the disk are only as strong as the login password.
- **Swift memory zeroisation**: `SecureBytes` and `SymmetricKey` are wiped; `String`/`Data` copies made by the runtime
  and SwiftUI cannot all be guaranteed zeroised (§10).
- **Clipboard managers ignoring `ConcealedType`/`TransientType`**, or any pasteboard poller (§10).
- **Forgotten MP, or lost SK with no Recovery Kit and no working Keychain**: unrecoverable by design; there is no
  backdoor (`RECOVERY.md`).
- **Coercion, hardware implants, side channels on a compromised host.**

---

## 5. Security controls summary

| Threat | Control | Where (under `Sources/VaultCore/`) |
|---|---|---|
| File/backup theft, offline MP guessing | Two-secret KEK `HKDF(MPK ‖ SKK)`, Argon2id floor + bounds, key-committing VMK wrap, uniform `authenticationFailed` | `Crypto/` (KeyHierarchy, Argon2id + KDFParameters, VaultHeader) |
| Record tampering, swap, transplant, rollback | Per-record HKDF key, AEAD with `"record"` AAD incl. `revision`, `state_mac`, generation mirror | `Crypto/` (RecordCipher, VaultHeader), `Vault/` (VaultStore), `Keychain/` |
| Header modification / KDF downgrade / replay | Canonical header as AAD, bounds-before-allocate, `generation`, `header_sha256` (UX) | `Crypto/` (VaultHeader, KeyHierarchy) |
| SK theft from keychain / Time Machine | HPKE wrap to SE P-256 `[.privateKeyUsage]`, `ThisDeviceOnly`, non-synchronizable, no plaintext fallback, Recovery Kit re-entry | `Crypto/` (HPKEWrap, RecoveryKit), `SecureEnclave/`, `Keychain/` (SecretKeyStore) |
| Touch ID misuse | Second SE key `[.privateKeyUsage, .biometryCurrentSet]`, VMK wrap with generation in AAD, `LAContext` settings, old blob replaced on rotation (§7.4) and deleted on restore / disable (§8.2) | `Crypto/` (HPKEWrap), `SecureEnclave/`, `Keychain/` |
| Metadata leakage from the file | Only id/crypto_version/revision in plaintext; padding; `WITHOUT ROWID`; `secure_delete`; `journal_mode = DELETE`; `auto_vacuum = FULL`; `VACUUM`; `.noindex`; 0700/0600 | `Vault/` (VaultStore), `Crypto/` (envelope) |
| Backup splicing / record rollback | Encrypted manifest over header hash + record set + `createdAt`; bounds before parse; atomic restore, no plaintext temp files | `Backup/` (BackupCodec, BackupManifest) |
| Tier-2 exposure in memory / on screen | Inner AEAD box under `tier2Key`, opened only on gated Reveal, 30 s auto-hide, dropped on lock | `Crypto/`, `Vault/` (item cache), app-layer gates |
| Logs, crash reports, core dumps | `SecureLog` (`StaticString` only), no value interpolation in assertions, `RLIMIT_CORE = 0`, `OSLogStore` sentinel test | `Logging/` (SecureLog), `Security/` |
| Key material lingering in RAM / swap | `SecureBytes` (`mlock` + `memset_s` via `CSecureMemory`), `SymmetricKey`, Lock drops everything | `Crypto/` (SecureBytes), `Sources/CSecureMemory` |
| Clipboard leakage | `.currentHostOnly`, `ConcealedType` + `TransientType`, change-count-guarded clear on timeout/lock/quit/sleep | `Security/` (pasteboard helper), app layer |
| Plaintext on disk from the app layer / accidental serialisation | No window restoration or `@SceneStorage`, non-sensitive `UserDefaults` only, text-input learning + Writing Tools off, no Spotlight/QuickLook; `Secret<T>` redacted and `Codable` only inside the vault blob codec | `Vault/` (Secret, VaultItem), `Sources/PrivateVaultApp`, container-scan test |
| Untrusted app bundle / network | Hardened runtime, App Sandbox with only `app-sandbox` + `files.user-selected.read-write` (no network entitlement) | `Scripts/build-app.sh`, `Packaging/` |

If a row above and the code ever disagree, the code is wrong (first paragraph of `SECURITY_ARCHITECTURE.md`).
