# PrivateVault — Security Audit (Version 1)

Date: 2026-08-19 · Scope: the whole repository at commit `c5f9e6b` (VaultCore, PrivateVaultApp, vendored CArgon2,
scripts, packaging, tests, documents) · Method: a hostile review by six independent lenses — cryptography,
data-at-rest/storage, authentication/Keychain/Secure Enclave, application layer (macOS), practical attacker with
the files, build/supply-chain/tests — reading the actual code, running the test suite and experimenting in scratch
copies; every finding was then re-checked by the developer against the code, a regression test was written where
possible, and the fix was applied before this document was finalised. A second, independent pass (six personas) is
recorded in section 5.

Status legend: **FIXED** (code changed, test added, commit referenced), **DOCUMENTED** (accepted residual risk,
stated in THREAT_MODEL/SECURITY_ARCHITECTURE), **OPEN** (not done in V1).

## 1. Summary

| Severity | Found | Fixed | Documented | Open |
|---|---|---|---|---|
| CRITICAL | 0 | – | – | – |
| HIGH | 8 | 8 | 0 | 0 |
| MEDIUM | 12 | 11 | 1 | 0 |
| LOW | 16 | 13 | 3 | 0 |
| INFO | 7 | 4 | 3 | 0 |

All CRITICAL/HIGH items are fixed; all MEDIUM items are fixed or explicitly documented. 85 automated tests pass
(`Scripts/run-tests.sh`); the signed sandboxed bundle verifies (`Scripts/verify-bundle.sh`).

## 2. HIGH findings

**PV-AUD-001 — `.gitignore` pattern `*RecoveryKit*` excluded `RecoveryKit.swift` and its tests from git** (build)
`.gitignore:24`. A fresh clone did not compile; the only kit decoder implementation was never committed.
*Fix:* pattern replaced by `*Recovery Kit*.txt`, files committed in `630323d`, build verified in a clean clone. **FIXED**

**PV-AUD-002 — Onboarding never showed the Recovery Kit** (app)
`AppModel.createVault` switched the phase to `.unlocked` before the kit step rendered, so the kit screen was
skipped entirely — a user could lose the only out-of-Mac copy of the Secret Key without ever seeing it.
*Fix:* new phase `.recoveryKit`; the main UI is reachable only after the user re-types the last kit group and
confirms (`AppModel.confirmRecoveryKitSaved`). **FIXED**

**PV-AUD-003 — `textSelection(.enabled)` on revealed secrets bypassed `SecureClipboard`** (app)
Select-all + ⌘C wrote the seed phrase to the raw pasteboard (Universal Clipboard, no concealed marker, never
cleared). *Fix:* text selection disabled on every secret `Text`; the NSTextView editor subclass (`SecretTextView`)
routes Copy/Cut through `SecureClipboard`, refuses drag-out, Services and pasteboard writes. **FIXED**

**PV-AUD-004 — Inline predictive text not disabled on secret editors** (app)
Wrong AppKit property (`isAutomaticTextCompletionEnabled`); typed seed words could be learned by the system
language model. *Fix:* `inlinePredictionType = .no` (+ `writingToolsBehavior = .none`, `mathExpressionCompletionType
= .no` on macOS 15); Recovery-Kit entry uses `PlainSecretTextField` (hardened NSTextField) instead of SwiftUI
`TextField`; both editors also enable Secure Event Input while focused. **FIXED**

**PV-AUD-005 — Recovery Kit stayed on screen after auto-lock (Settings sheet)** (app)
The Settings scene is outside `RootView`'s phase switch; the kit sheet survived lock and became capturable.
*Fix:* `dismissWhenLocked()` on every Settings sheet, 90 s auto-hide for the kit, window capture blocked whenever
secrets can be on screen (`.unlocked` or `.recoveryKit`). **FIXED**

**PV-AUD-006 — Secret Key regeneration committed the vault under the new key before storing/showing it** (storage, crypto)
A Keychain failure or crash between `rotate()` and `storeSecretKey()` left the vault permanently unopenable.
*Fix:* two-phase: new key written as `sk-pending:` **before** rotation, promoted after; unlock accepts the pending
key (`deviceSecretKey`); the kit is always returned, the UI flags "this kit is the only copy" when the Keychain
refused it. Test `secret_key_regeneration_is_crash_safe_and_survives_keychain_failure`. **FIXED**

**PV-AUD-007 — One tampered record bricked the whole vault with "wrong password"** (attacker, crypto)
`VaultSession.loadAndVerify` aborted on the first record that failed to authenticate. *Fix:* per-record quarantine
(`unreadableRecordIDs`, `IntegrityWarning.unreadableRecords`), backups exclude quarantined records, user can purge
them; unlock is refused only when *every* record fails (`corrupted("all records unreadable")`). Test
`tampering_with_records_or_header_is_detected`. **FIXED**

**PV-AUD-008 — Touch ID path did not authenticate the header** (attacker)
The bio blob was bound only to `generation`; a modified header (salt/params) unlocked via Touch ID while every
password-gated operation silently failed. *Fix:* bio AAD = `0x02 ‖ vaultID ‖ header_sha256`; the bio path also
compares the file's `header_sha256` with the value pinned in the device record and refuses (`biometryInvalidated`)
on mismatch; header checksum verified on every unlock (`corrupted("header checksum")` for naive edits). Test
`touch_id_path_refuses_a_modified_header`. **FIXED**

## 3. MEDIUM findings

| ID | Finding | Resolution |
|---|---|---|
| PV-AUD-009 | Whole-file rollback to an older copy with the same header generation was undetected; pinned `headerSHA256` was never compared | Device record now mirrors the last `state_mac` after **every** commit (`VaultSession.onStateChanged`); unlock emits `.fileRollback` when the same generation carries a different MAC; `headerSHA256` compared on the bio path. Test `whole_file_rollback_same_generation_is_detected`. **FIXED** |
| PV-AUD-010 | `rewrapBiometric` sealed the VMK to a public key read back from a replaceable Keychain item (exfiltration channel for a local process) | Re-wrap now always creates a **fresh** biometric SE key (`enableBiometric`) and never trusts a stored public key; if that fails Touch ID is disabled instead. **FIXED** |
| PV-AUD-011 | Restore deleted the existing vault's Secret-Key/Touch-ID records before the point of no return | Orphan cleanup moved after the atomic swap; temp file removed on failure; stale `-journal` removed before the swap. Test `failed_restore_keeps_existing_vault_and_its_secret_key`. **FIXED** |
| PV-AUD-012 | Post-COMMIT `VACUUM` failure desynchronised session and disk (subsequent saves under old keys) | `VACUUM` is best-effort (logged) inside `VaultStore.writeHeader/replaceAll`; the session adopts the committed keys regardless. **FIXED** |
| PV-AUD-013 | Hostile backup `createdAt` near `Int64.max` trapped (`Int64(Double)`) during restore | `createdAt` kept as `Int64`, bounded at parse (2020…2200) → `backupInvalid("creation time")`. Test `hostile_backup_timestamp_is_rejected_without_crashing`. **FIXED** |
| PV-AUD-014 | 256-byte padding buckets let a file thief infer item kind (seed-phrase wallets landed in 768/1024 B) | Every record now pads to a multiple of 4 KiB (minimum 4 KiB): login, API key, note, recovery codes and 24-word wallet share one bucket. Spec §4.1/§4.3 updated. **FIXED** |
| PV-AUD-015 | No Secure Enclave ⇒ Secret Key stored raw in the Keychain with no warning | `secretKeyHardwareBound` surfaced: onboarding text is conditional, Settings › Security shows a persistent note. **FIXED** |
| PV-AUD-016 | Context-menu "Delete…" deleted immediately without confirmation | Confirmation dialog added (`pendingDelete`). **FIXED** |
| PV-AUD-017 | Spec §5.2 claimed a tested record migrator that did not exist; schema_version error paths untested | Spec corrected (V1 = single crypto_version, unknown versions quarantined/refused, schema-migration planner); tests `VersionPathTests`, `schema_migration_plan_is_ordered_and_gapless`; golden v1 fixture vault + backup committed. **FIXED** |
| PV-AUD-018 | Pre-commit secret scan missed renames (`--diff-filter=ACM`) and scanned the working tree instead of the staged blob | `ACMRT`, `git show :path`, binary detection fixed; verified in a scratch clone. **FIXED** |
| PV-AUD-019 | Recovery-Kit scan pattern matched only the canonical upper-case hyphenated form | Case-insensitive, space-or-hyphen separated, lookalike-tolerant pattern (separators required to avoid matching hex test vectors). **FIXED** |
| PV-AUD-020 | Attacker with temporary access to the unlocked Mac (vault locked) can use the non-biometric SE key + Keychain item to obtain the Secret Key and then crack the Master Password offline | Inherent to a non-biometric SE key; `THREAT_MODEL.md` §3.6 states it; an in-process unlock throttle (2^(n−3) s after 3 failures) was added; a future "require Touch ID for every unlock" option is listed for V1.1. **DOCUMENTED** |

## 4. LOW / INFO findings

| ID | Finding | Resolution |
|---|---|---|
| PV-AUD-021 | KDF upgrade could lower one dimension (e.g. more passes, less memory) | `KDFParameters.upgraded(to:)` = element-wise max. Test `kdf_upgrade_never_lowers_a_dimension`. **FIXED** |
| PV-AUD-022 | KDF upgrade bumped the generation before the rollback comparison (masked a one-generation rollback) | Rollback warnings computed from the pre-upgrade header. **FIXED** |
| PV-AUD-023 | `HPKEWrap.open` collapsed LocalAuthentication errors into `authenticationFailed`; Touch ID cancel reported as "settings changed" | Non-CryptoKit errors propagate; `SystemSecureEnclave` maps LA codes; `DeviceKeyStore.loadBiometricVMK` distinguishes cancel/unavailable/invalidated. Test `touch_id_cancel_is_reported_as_cancel_not_as_invalidation`. **FIXED** |
| PV-AUD-024 | `header_sha256` never verified at unlock | Verified in `readHeader` (UX: "corrupted" vs "wrong password"). **FIXED** |
| PV-AUD-025 | Root-key plaintext left in unwiped `Data` copies on hot paths | `Data.wipe()` added and used after VMK unwrap, HPKE open, Recovery-Kit decode/encode, raw-mode SK load (best effort; documented CoW limits). **FIXED** |
| PV-AUD-026 | Restore left `vault.restore.tmp` on failure; stale `-journal` could be replayed | Cleaned up / removed before swap. **FIXED** |
| PV-AUD-027 | Backup `createdAt` not shown before restore | Shown (with record count) after choosing the file, in onboarding and Settings. **FIXED** |
| PV-AUD-028 | Recovery-Kit text export written with default umask; export errors swallowed | 0600 permissions; write errors shown; success confirmation. **FIXED** |
| PV-AUD-029 | `mlock`/`munlock` page-granular: one `SecureBytes` deinit unpinned neighbours | Each `SecureBytes` owns its own page (`posix_memalign(pagesize)`). **FIXED** |
| PV-AUD-030 | Pre-commit hook not active on a fresh clone (local `core.hooksPath`) | Documented in README; `build-app.sh` prints a reminder. **FIXED** |
| PV-AUD-031 | Secret-scan gaps (camelCase `privateKey`, PGP/PKCS#8 PEM, GitHub fine-grained/OpenAI tokens, ASIA keys; forbidden-type list missing `.provisionprofile/.p8/.keychain-db/.cer`) | Patterns broadened, lists extended. **FIXED** |
| PV-AUD-032 | KDF floor not enforced at creation / policy change | `VaultManager` enforces `meetsFloor` unless `allowWeakKDFForTesting` (tests only). **FIXED** |
| PV-AUD-033 | `SecureLog.Value.category(String)` accepted an arbitrary String | Now `StaticString`; `VaultError.caseName` is `StaticString`. **FIXED** |
| PV-AUD-034 | Secret editors not under Secure Event Input | `EnableSecureEventInput` while a secret editor/kit field is first responder. **FIXED** |
| PV-AUD-035 | Window restoration only disabled for launch-time windows | `isRestorable = false` applied to every window on key-window notifications. **FIXED** |
| PV-AUD-036 | Masked password row revealed the length via bullet count | Fixed 12 bullets. **FIXED** |
| PV-AUD-037 | `accessibilityProtectedContent` is advisory for the NSTextView editor | Revealed SwiftUI texts are hidden from the accessibility tree; the editor keeps AX editing for assistive users — a process holding the Accessibility permission can read it. **DOCUMENTED** (THREAT_MODEL §4) |
| PV-AUD-038 | Spec §10 claimed an `OSLogStore` assertion; the test checks the in-memory sink | Spec reworded. **FIXED** |
| PV-AUD-039 | `build-app.sh` dead branch would ship an unsigned dylib; `CSecureMemory.h` declaration outside include guard; `SQLITE_DBCONFIG_DEFENSIVE` return code ignored | All three fixed. **FIXED** |
| PV-AUD-040 | Backup size bound (512 MiB) checked after the file is read | The file is read by the user's open panel anyway; bound kept. **DOCUMENTED** |
| PV-AUD-041 | No unlock throttling | In-process throttle added (see PV-AUD-020). **FIXED** |
| PV-AUD-042 | `vault.restore.tmp`/VACUUM temp files inside the container | Contain ciphertext only; removed on completion/failure. **DOCUMENTED** |

## 5. Second independent review (six personas, after the fixes)

1. **macOS security engineer** — Re-checked: entitlements exactly `app-sandbox` + `files.user-selected.read-write`
   (`Scripts/verify-bundle.sh`), hardened runtime flag, no `get-task-allow` in release, `RLIMIT_CORE=0`, saved
   state deleted, `isRestorable=false` on all windows, `NSWindow.sharingType=.none` while secrets can be shown,
   Secure Event Input on password fields and secret editors, no `@AppStorage/@SceneStorage`, `UserDefaults` keys
   limited to four non-sensitive settings, Spotlight excluded (`Vault.noindex`), `.privatevault` UTI = `public.data`.
   Residual: ad-hoc signature has no certificate chain (THREAT_MODEL §4); legacy-keychain ACL prompt after rebuilds.
2. **Cryptography engineer** — Re-checked against the code: fresh CSPRNG nonce on every seal; AAD constructions
   injective and complete (canonical header; `"record"‖vaultID‖recordID‖version‖revision`; tier-2 field name;
   backup manifest with header hash, sorted ids, per-blob hashes, created_at); commitment prefix on both wraps;
   HKDF labels distinct and versioned; Argon2id vendored reference verified by SHA-256 and RFC 9106 §5.3 vector;
   HKDF RFC 5869 A.1–A.3; AES-GCM Wycheproof vectors incl. invalid tags; HPKE RFC 9180 A.3; KEK chain
   cross-checked with OpenSSL; constant-time compares for MACs. Residual: GCM random-nonce bound (negligible at
   personal scale, per-record keys); Swift `String` copies of plaintext items are not zeroised (documented).
3. **Application security engineer** — Re-checked: every password-gated operation is enforced in `VaultManager`
   (not only in the UI); `Secret<T>`/`VaultItem` refuse serialisation outside the vault codec; redaction in
   `description`/`Mirror`; `SecureLog` takes only `StaticString` + closed value set, sentinel test passes;
   clipboard writes are concealed/transient/current-host-only and cleared on timeout/lock/quit/sleep, never read;
   tier-2 reveal needs system authentication and auto-hides; all Settings sheets close on lock; context-menu
   delete confirms. Residual: clipboard managers that ignore the convention (documented).
4. **Attacker who stole `vault.sqlite`** — Obtains header (non-secret), wrapped VMK, record ids/revisions and
   uniform 4 KiB ciphertext blobs; cannot test a single password guess (KEK needs the 256-bit Secret Key); cannot
   move/alter/roll back records without a warning (AAD, state MAC, device mirror); cannot make the app crash or
   allocate unbounded memory (header bounds validated first). Confirmed by tests `tampering_with_records_or_header…`,
   `whole_file_rollback_*`, `parse_rejects_untrusted_input_before_kdf`.
5. **Attacker who stole a `.privatevault` backup** — Same as 4 plus nothing: the file contains no Secret Key, no
   plaintext, no titles (test `backup_export_restore_disaster_recovery` asserts no sentinel, password, kit or SK
   bytes appear); splicing/dropping/duplicating/back-dating records is rejected by the manifest (test
   `corrupted_or_spliced_backups_are_rejected`); hostile timestamps no longer crash (`hostile_backup_timestamp…`).
   Residual: an entire older legitimate backup can be substituted (authenticated, not fresh — shown `createdAt`).
6. **Attacker who compromised the future server** — Nothing is built yet; the V1 data model already exposes only
   opaque `EncryptedRecord`s (id, crypto_version, revision, blob), the non-secret header, and would expose device
   public keys. `FUTURE_SYNC_ARCHITECTURE.md` requires the Secret Key to be transferred device-to-device (never
   the VMK, never through the server), per-device signed manifests and monotonic generations; a sync build would
   need the network entitlement, which weakens the V1 kernel-level guarantee — to be decided then.

## 6. Coverage of the required test list

Master Password unlock · wrong password · wrong Secret Key · encryption/decryption · ciphertext tampering ·
authentication-tag failure · different ciphertext/nonces for identical plaintext · password change (re-wrap and
rotation) · VMK wrapping/unwrapping · database corruption · record/schema version handling + golden v1 fixture ·
Keychain unavailable · Touch ID cancellation / invalidation / header binding · clipboard auto-clear · automatic lock
· sleep/session lock · backup · restore · incorrect backup password/key · corrupted/spliced backup · large vault
(2000 records) · Unicode (NFC/NFD) · empty fields · very long values (1 M characters) · wallet seed phrase storage
(tier-2 inner box) · private key masking (stays sealed in memory until reveal) · no secret values in logs /
serialisation / on disk — all present in `Tests/VaultCoreTests` (95 tests as of 2026-08-26, incl. folders §8). Real Secure Enclave + Keychain
integration tests are opt-in (`PV_DEVICE_TESTS=1`). Not automated: SwiftUI interaction flows (no UI automation
without Xcode); these were reviewed by reading and by launching the app.

## 7. Known limitations carried into V1 (honest list)

- Malware in the logged-in session, keyloggers with Input Monitoring, screen recording of revealed values,
  memory reads while unlocked, and a trojaned app bundle are out of scope (THREAT_MODEL §4).
- The non-biometric Secure-Enclave key that wraps the Secret Key can be used by any process running as the user
  on this Mac; combined with the Keychain item this yields the Secret Key (then the password still has to be
  cracked at Argon2id cost). A "Touch ID required for every unlock" option is a V1.1 candidate.
- Rollback detection depends on this Mac's Keychain mirror; a brand-new Mac has no baseline.
- The legacy login keychain is used because an ad-hoc signed app cannot use the Data-Protection keychain;
  after every rebuild macOS shows one Keychain consent dialog.

## 8. Post-V1 change review: folders (2026-08-26)

Surface added: `VaultFolder` records (§6.1 of the architecture), `VaultItem.folderID`, session operations
create / rename / delete / move, and the sidebar/editor UI. Reviewed against the same questions as the V1 audit:

| Question | Result |
|---|---|
| Does anything about folders leave the ciphertext? | No. Folder records use the record envelope unchanged (per-record key, AAD, 4 KiB bucket); names are never logged, never put in the window title (`navigationTitle` deliberately not used), never in UserDefaults. Test: sentinel folder names absent from the vault directory and from backups; all 7 records (5 items + 2 folders) have identical blob sizes; `sqlite_master` contains no folder table/column. |
| Format compatibility | Item JSON is byte-for-byte the v1 layout when `folderID` is nil (`encodeIfPresent`); folders are tagged `doc:"folder"`; unknown tags → `corrupted`. Golden v1 vault + backup still open (test asserts no folders / nil folderIDs). No schema or crypto version bump needed. |
| Integrity / rollback | Folder records are ordinary entries of the state MAC; delete-folder + unfile-members is one transaction with one new MAC (test: re-unlock after delete shows no integrity warning). A folder record tampered on disk is quarantined like an item; member items degrade to "no folder" (test). |
| Rotation / backup / restore | `reencryptAll` re-seals folders under the new keys (test: folder blob changes after rotation); backup verify authenticates folder records via `openDocument`; restore is unchanged (test round-trips folder membership and a tier-2 reveal). |
| Injection of a folder id as an item id | Refused by the session (`invalidInput`); dangling `folderID` on save is normalised to nil (test). |
| Drag & drop payload | The dragged string is only the item's random record id; drops are validated against the in-memory item list and folder existence. |
| Tier-2 exposure | Moves/renames re-seal items with tier-2 boxes still sealed (test asserts `isSealed` after move + unlock). |

No new findings. Not automated (as before): the SwiftUI flows — create folder, rename, delete with items inside,
drag onto a folder, editor picker, .env import into a folder — reviewed by reading and by launching the app.

