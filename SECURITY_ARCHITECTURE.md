# PrivateVault — Security Architecture (Version 1)

This document is the normative specification of PrivateVault's cryptography and storage. The code in
`Sources/VaultCore` implements exactly what is written here; the tests in `Tests/VaultCoreTests` pin the
byte-level formats with known-answer vectors. If the code and this document ever disagree, that is a bug.

Companion documents: `THREAT_MODEL.md` (what we defend against and what we do not),
`RECOVERY.md` (which loss scenarios are recoverable), `FUTURE_SYNC_ARCHITECTURE.md`,
`DEPENDENCY_SECURITY.md`, `SECURITY_AUDIT.md`.

---

## 0. Design summary in one paragraph

Every secret is encrypted on this Mac with AES-256-GCM under keys that are derived from a random
**Vault Master Key (VMK)**. The VMK is never stored in the clear: it is wrapped with a **Key Encryption Key
(KEK)** that can only be recomputed from **both** the user's Master Password (memory-hard Argon2id) **and** a
random 256-bit **Secret Key** that lives outside the vault file (Secure-Enclave-wrapped in the macOS Keychain,
and on paper in the Recovery Kit). Therefore the vault file, a backup, a Time Machine copy or a future sync
server contain only ciphertext and non-secret parameters, and an attacker who has the files but not the Secret
Key cannot even *start* guessing the Master Password. There is no developer key, no universal recovery key,
no server-side component and no network access.

---

## 1. Primitives (all established, none home-made)

| Purpose | Primitive | Implementation |
|---|---|---|
| Password hashing / key stretching | **Argon2id** (RFC 9106, version 0x13) | Vendored PHC reference C implementation (`Sources/CArgon2`, pinned, hash-verified) |
| Key derivation / separation | **HKDF-SHA256** (RFC 5869) | Apple CryptoKit `HKDF<SHA256>` |
| Authenticated encryption | **AES-256-GCM**, 96-bit nonce, 128-bit tag | Apple CryptoKit `AES.GCM` (hardware accelerated, corecrypto) |
| Public-key wrapping to Secure Enclave | **HPKE** (RFC 9180) base mode, `DHKEM(P-256, HKDF-SHA256)`, HKDF-SHA256, AES-256-GCM | Apple CryptoKit `HPKE` with `SecureEnclave.P256.KeyAgreement.PrivateKey` |
| Integrity MAC | **HMAC-SHA256** | CryptoKit `HMAC<SHA256>` |
| Hashing | **SHA-256** | CryptoKit |
| Randomness | OS CSPRNG | `SystemRandomNumberGenerator` / `SecRandomCopyBytes` (Apple) |
| Memory hygiene | `memset_s`, `timingsafe_bcmp`, `mlock` | Darwin libc via `Sources/CSecureMemory` |

Nothing else. No SHA256(password)-as-key, no custom ciphers, no third-party crypto packages.

---

## 2. Key hierarchy

```
 Master Password (MP)                         Secret Key (SK)
 user memory only, never stored               256-bit CSPRNG, generated at vault creation
 NFC-normalized UTF-8, no trimming            stored: Keychain (SE-wrapped) + Recovery Kit (paper)
        │                                            │
        │ Argon2id(m, t, p, salt16)                  │ HKDF-SHA256(IKM=SK, salt=vaultID,
        │ (parameters + salt live in header)         │            info="privatevault/v1/secret-key")
        ▼                                            ▼
      MPK  (32 bytes)                              SKK (32 bytes)
        └──────────────────────┬──────────────────────┘
                               │ HKDF-SHA256(IKM = MPK ‖ SKK, salt = vaultID,
                               │            info = "privatevault/v1/kek/a256gcm")
                               ▼
                             KEK (32 bytes)  — exists only in memory during unlock
                               │ AES-256-GCM wrap, AAD = canonical header bytes (§3.1)
                               ▼
                  wrapped_VMK (stored in vault_header)
                               │ unwrap
                               ▼
                             VMK (32 bytes CSPRNG) — exists only in memory while unlocked
        ┌──────────────────────┼───────────────────────┬──────────────────────┬────────────────────┐
        ▼                      ▼                       ▼                      ▼                    ▼
 recordRootKey           tier2Key                vaultStateKey          backupManifestKey      (reserved labels:
 "…/v1/record-encryption" "…/v1/tier2"           "…/v1/vault-state"     "…/v1/backup-manifest"  metadata, search-index,
        │                                                                                        sync-auth)
        │ HKDF(info = "privatevault/v1/record/" ‖ recordID)
        ▼
 per-record key (32 bytes)  → AES-256-GCM of the record envelope (§4)
```

All HKDF calls: HKDF-SHA256, `salt = vaultID` (16 raw bytes), `info` = the ASCII label shown (plus the
documented suffix), output 32 bytes. Labels are versioned (`/v1/`); a label is never reused with different
semantics. The VMK itself is never used directly as an AEAD key. The master password is combined with the
Secret Key through HKDF (not XOR) so no linear relation between the two inputs exists.

### 2.1 Why two secrets

- **Master Password** protects against an attacker who obtains this Mac's Keychain contents (e.g. malware in the
  user session, or a login-password-cracked keychain copy) but not the password.
- **Secret Key** protects against an attacker who obtains the vault file, a backup, a Time Machine copy or the
  future sync server: the KEK depends on 256 random bits they do not have, so offline password guessing is
  impossible regardless of password strength.

### 2.2 Master Password processing

1. Input is taken via `SecureField` (Secure Event Input on macOS).
2. Normalised with Unicode **NFC** (`precomposedStringWithCanonicalMapping`), encoded as UTF-8. No trimming, no
   case folding (leading/trailing whitespace produces a warning in the UI). Empty rejected; > 1024 bytes rejected.
3. The normalisation identifier `pw_norm = 1` is recorded in the canonical header so it can evolve.
4. Policy for new vaults: minimum 12 characters and an estimated entropy ≥ 50 bits (local estimator, no
   network) — the Secret Key makes offline attacks infeasible, but the password is the *only* barrier against an
   attacker who also got the Secret Key.

### 2.3 Argon2id parameters

- Version 0x13, `m` (KiB), `t` (passes), `p` (lanes), 16-byte CSPRNG salt, 32-byte output.
- **Production defaults** were chosen with `Scripts/benchmark-kdf.sh` on the owner's MacBook Air M1 (8 GB), release
  build, 2026-08-19: `m = 256 MiB, t = 6, p = 4` ≈ 0.65 s per unlock (256 MiB/t=3 measured 0.33 s; 512 MiB/t=3
  0.73 s but was rejected because this Mac has 8 GB RAM and heavy swap use). They live in `KDFParameters.current`.
  Floor for vaults created by this app: **m ≥ 64 MiB, t ≥ 3**. A test asserts `KDFParameters.current ≥ floor`.
- Parameters are **untrusted input** when read from a header or backup: the app validates
  `m ∈ [8 MiB, 1 GiB]`, `t ∈ [1, 16]`, `p ∈ [1, 4]`, `salt = 16 B` **before** allocating memory or deriving.
  Out-of-range ⇒ "vault header is invalid"; never repaired with defaults.
- **Upgrade policy**: when a vault unlocks with the Master Password and its header parameters are below
  `KDFParameters.current`, the header is re-created with the current parameters (§7.3). Parameters are never
  lowered. Upgrades cannot happen on the Touch-ID path (no password available) — they happen on the next
  password unlock.

### 2.4 The Secret Key and the Recovery Kit

- `SK` = 32 bytes from the OS CSPRNG, generated once per vault.
- `sk_id` = first 4 bytes of `HKDF-SHA256(IKM=SK, salt=vaultID, info="privatevault/v1/sk-id")` — a non-secret
  identifier stored in the header (and in every backup); when a typed Recovery Kit does not match it the app says
  "this Recovery Kit does not belong to this vault" instead of reporting a wrong password.
- **Recovery Kit string** (`RecoveryKit.swift`):
  `PV1-XXXXX-XXXXX-…` = literal prefix `PV1-`, then 52 data characters + 3 check characters in Crockford Base32
  (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`) grouped in 11 groups of 5 separated by `-`.
  Check = first 15 bits of `SHA-256("privatevault-sk-v1" ‖ SK)`. The decoder upper-cases, strips spaces/hyphens,
  maps `I`/`L`→`1`, `O`→`0`, verifies length and checksum **locally** before any unlock attempt, so a typo is
  reported as a typo, not as "wrong password".
- Displayed once at creation; the user must re-type one group to continue. Re-displaying or saving the kit as a
  text file later requires re-entering the Master Password and shows a warning that the kit is as sensitive as
  the vault.

---

## 3. Vault header

### 3.1 Canonical header bytes (`VaultHeader.canonicalBytes`)

Exactly these bytes, in this order, big-endian integers, no framing beyond what is shown. They are the **AAD of
the wrapped VMK** and the **preimage of `header_sha256`**. A golden test pins the hex of a fixed header.

| Field | Size | Value in v1 |
|---|---|---|
| magic | 4 | `'PVLT'` |
| format | u8 | `1` |
| vaultID | 16 | random UUID bytes |
| kdf_id | u8 | `1` = Argon2id v0x13 |
| m_kib | u32 | memory in KiB |
| t | u32 | passes |
| p | u8 | lanes |
| salt_len | u8 | `16` |
| salt | salt_len | CSPRNG |
| pw_norm | u8 | `1` = NFC |
| wrap_alg | u8 | `1` = AES-256-GCM |
| generation | u32 | starts at 1, +1 on every header rewrite (password change, KDF upgrade, rotation) |
| created_at | i64 | Unix seconds of vault creation |

Unknown `format` (higher than supported) ⇒ refuse with "created by a newer version" — never attempt to parse.

### 3.2 Wrapped VMK

`wrapped_VMK = AES-256-GCM.seal(key = KEK, nonce = 12 B CSPRNG, plaintext = 0x00×32 ‖ VMK, aad = canonical header)`
stored as `nonce ‖ ciphertext ‖ tag` (12 + 64 + 16 = 92 bytes). After a successful open the first 32 bytes are
checked to be zero (the "padding fix" that makes the wrap key-committing: a wrong key can not produce a
plausible-looking VMK). Wrong password, wrong Secret Key, modified header (including KDF parameter downgrade)
and modified ciphertext all fail the same way: one uniform `VaultError.authenticationFailed`. There is no
separate verifier/hash of the password or key.

### 3.3 Other header fields (stored in the `vault_header` row, not part of the canonical bytes)

| Field | Why it exists / what it leaks |
|---|---|
| `wrapped_vmk` | ciphertext (§3.2) |
| `header_sha256` | unkeyed SHA-256 of canonical bytes ‖ wrapped_vmk; UX only: lets the app say "header corrupted" instead of "wrong password". An attacker can recompute it; it is not a security control. |
| `sk_id` | 4 non-secret bytes (§2.4) |
| `state_mac` | HMAC over the record list (§5.3) |
| `schema_version` | integer for migrations |

---

## 4. Record envelope

### 4.1 Storage row

`records(id BLOB(16) PRIMARY KEY, crypto_version INTEGER, revision INTEGER, blob BLOB) WITHOUT ROWID`

| Plaintext column | Why plaintext | What it leaks |
|---|---|---|
| `id` | primary key; random UUID, needed to address records and for future sync | nothing (random) |
| `crypto_version` | needed to pick the envelope format before decrypting | app version era |
| `revision` | monotonic per-record counter, authenticated inside the AAD and used by the state MAC (§5.3) and future sync conflict resolution | how many times a record was edited |
| `blob` | ciphertext | size class only: every ordinary record pads to one 4 KiB bucket (§4.3); only unusually large notes stand out |

**Everything else** — item type, title, website, username, password, notes, tags, favourite flag, creation and
modification timestamps, last-used time, wallet chain, addresses, seed phrases, private keys — is inside the
ciphertext. A database thief cannot tell a wallet from a login (all ordinary records have the same padded size),
cannot count how many logins exist, and cannot learn when records were created.

### 4.2 Envelope format (crypto_version = 1)

```
blob = [0x01][nonce 12 B][AES-256-GCM ciphertext][tag 16 B]
key  = HKDF-SHA256(IKM = recordRootKey, salt = vaultID, info = "privatevault/v1/record/" ‖ recordID(16 B))
aad  = "record" ‖ vaultID(16) ‖ recordID(16) ‖ crypto_version u32be ‖ revision u64be
```
A fresh CSPRNG nonce is drawn for **every** encryption; identical plaintexts always produce different
ciphertexts. With 2^32 encryptions the random-nonce collision probability is ≈ 2^-33 per key; a personal vault
performs orders of magnitude fewer encryptions and each record has its own key, so the risk is negligible.
Binding `recordID` and `vaultID` in the AAD means a ciphertext cannot be moved to another record or another vault;
binding `revision` means an old version of a record cannot be silently restored without also breaking the
state MAC.

### 4.3 Plaintext layout and padding

`plaintext = [u32be length of JSON][JSON bytes][zero padding]` padded to the next multiple of 4 KiB (minimum
4 KiB). The JSON is the `VaultItem` document (§6). A login, an API key, a note, a set of recovery codes and a wallet
with a 24-word seed phrase and private key all fit in the first bucket, so the ciphertext size does not reveal the
item kind or the seed length; only very large notes (> ~4 KB of text) occupy more buckets.

### 4.4 Tier-2 fields (seed phrase, private key)

Wallet seed phrases and private keys are the highest-sensitivity data. Inside the JSON they are stored as an
**inner AEAD box**, not as plain strings:

```
tier2Box = [0x01][nonce 12][AES-256-GCM(key = tier2Key, aad = "tier2" ‖ vaultID ‖ recordID ‖ fieldName)][tag 16]
```
When the vault is unlocked the app keeps the *outer* record decrypted (title, chain, public address) but keeps
the inner boxes as ciphertext in memory. They are opened only when the user presses **Reveal** (after system
authentication, §8.3) and the plaintext is dropped again when the field is hidden, the item is closed or the vault
locks. This shortens the time the most valuable plaintext exists in process memory; it is defence in depth, not
a separate trust boundary (the tier-2 key is derived from the VMK, so it is available while unlocked).

---

## 5. Database

### 5.1 File and connection

- Location (sandboxed): `~/Library/Containers/com.kostastoulis.privatevault/Data/Library/Application Support/PrivateVault/Vault.noindex/vault.sqlite`
  (`.noindex` keeps Spotlight out). Directory mode `0700`, file mode `0600`.
- Opened with `SQLITE_OPEN_READWRITE | CREATE | NOFOLLOW | EXRESCODE`, `SQLITE_DBCONFIG_DEFENSIVE`,
  `PRAGMA journal_mode = DELETE` (single process; no lingering WAL files), `PRAGMA secure_delete = ON` (set on
  every connection — it is per-connection), `PRAGMA auto_vacuum = FULL`, `PRAGMA integrity_check` on open,
  `VACUUM` after key rotation and bulk deletes so old ciphertext does not linger in free pages.
- Residual risk (documented, not fully controllable): APFS snapshots, Time Machine and the rollback journal may
  retain *old ciphertext* blocks. They contain no plaintext; the only effect is that an attacker could observe
  that a record changed.

### 5.2 Schema (schema_version = 1)

```
meta(key TEXT PRIMARY KEY, value BLOB)            -- schema_version
vault_header(id INTEGER PRIMARY KEY CHECK(id = 1), canonical BLOB, wrapped_vmk BLOB,
             header_sha256 BLOB, sk_id BLOB, state_mac BLOB)
records(id BLOB PRIMARY KEY, crypto_version INTEGER NOT NULL, revision INTEGER NOT NULL, blob BLOB NOT NULL) WITHOUT ROWID
```
Schema migrations are an ordered, gapless list keyed by `schema_version` (`SchemaMigrations.plan`), each run in
one transaction at open; a database with a *higher* schema version than the app knows is refused
(`unsupportedFormat`). Record envelopes carry their own `crypto_version`; V1 supports exactly version 1 — a record
with any other version makes the unlock fail (`unsupportedFormat`) rather than being silently skipped. When a
future version 2 is introduced, `RecordCodec.open` will accept both and the session will re-seal v1 records at
the current version on their next write; the committed golden fixture (`Tests/VaultCoreTests/Fixtures/golden-v1.*`)
guarantees that v1 vaults and backups keep opening.

### 5.3 Authenticated vault state (rollback / deletion detection)

`state_mac = HMAC-SHA256(vaultStateKey, "state" ‖ vaultID ‖ generation u32be ‖ count u32be ‖ sorted list of (recordID 16 B ‖ revision u64be))`

It is recomputed and written in the **same transaction** as every record insert/update/delete. On unlock the app
recomputes it from the table and compares: a mismatch means a record was deleted, replaced with an older authentic
version, or the whole table was tampered with outside PrivateVault. The user is warned ("vault modified outside
PrivateVault or rolled back") and may continue.

**Whole-file rollback.** The device record that holds the Secret Key also mirrors the last seen `generation`,
`header_sha256` and — updated after **every** committed write — the last `state_mac`. On unlock: a lower generation
⇒ "generation rollback" warning; the same generation but a different `state_mac` than the mirrored one ⇒ "file
rollback" warning (an older authentic copy was put back; a legitimate Time Machine restore can be acknowledged —
the warning is shown once and the mirror is re-pinned). The Touch ID path additionally refuses to run at all if the
file's `header_sha256` differs from the mirrored one (§8.2).

**Unreadable records.** A record whose ciphertext does not authenticate (tampered, bit-rot, unknown version) does
not brick the vault: the unlock succeeds once the VMK has been verified, the record is quarantined (kept in the
file, hidden from the UI, excluded from backups), the user sees an "unreadable records" warning and may purge them.
If *every* record fails, the unlock is refused (`corrupted`) — that is a wrong key for the data, not partial damage.

Limits: the state MAC is keyed with a key derived from the VMK, so an attacker who can *unlock* the vault can
also recompute it — it detects tampering by someone who cannot decrypt, which is the at-rest threat model. The
mirror lives in this Mac's Keychain: on a different Mac (or after the Keychain item is lost) there is no baseline
and the first unlock cannot detect a rollback.

---

## 6. Item model

`VaultItem { id, kind, title, favorite, tags[], createdAt, updatedAt, lastUsedAt, payload }` where payload is one of
`login(website, username, password, notes)`, `apiCredential(service, apiKey, apiSecret, environment, notes)`,
`wallet(name, blockchain, publicAddress, seedPhrase†, privateKey†, derivationPath, notes)`, `secureNote(body)`,
`recoveryCodes(service, codes[], notes)`. † = tier-2 inner box.

`Secret<T>` wraps every sensitive value: its `description`, `debugDescription` and `Mirror` are redacted, and its
`Codable` conformance **throws** unless the encoder/decoder was created by the record envelope codec
(`userInfo[.vaultBlobCodec] == true`). Accidentally serialising a model with `JSONEncoder()` anywhere else fails
loudly instead of leaking.

---

## 7. Lifecycle operations

### 7.1 Create vault
`vaultID ← random; SK ← random; VMK ← random; salt ← random; MPK ← Argon2id(MP); KEK ← HKDF; wrapped_VMK ← wrap;
header generation = 1; state_mac over empty list; store SK (§8.1); show Recovery Kit.`

### 7.2 Unlock
Password path: `read header → validate bounds → Argon2id → KEK → open wrapped_VMK (check zero prefix) → derive
subkeys → verify state_mac → decrypt all outer envelopes into memory (tier-2 stays boxed)`.
Touch ID path: `SEP-enforced HPKE open of bio blob → VMK → same from "derive subkeys"`.

### 7.3 Change Master Password (default: re-wrap only)
`verify current MP (full unlock) → new salt → MPK' → KEK' → new canonical header (generation+1, current KDF params)
→ wrapped_VMK' → self-check: open wrapped_VMK' with KEK' → single transaction: UPDATE vault_header → VACUUM`.
Records are untouched (this is the property the key hierarchy was built for). The old header is physically
overwritten and vacuumed, but copies in old backups/snapshots remain openable with the **old** password + SK;
see `RECOVERY.md` and the rotation option below.

### 7.4 Key rotation (optional on password change; mandatory on "Regenerate Secret Key")
`VMK' ← random; derive subkeys'; re-encrypt every record (new nonce, revision+1, crypto_version current);
new header (generation+1); new state_mac; all in one transaction; re-wrap Touch-ID blob under VMK' (public-key
operation, no Touch ID prompt); VACUUM`. After rotation, old headers and old backups no longer decrypt new
records.

**Secret Key regeneration is crash-safe:** the new key is written to the device store as a *pending* record
**before** the vault is rewritten, then promoted; an interrupted regeneration is repaired at the next unlock (the
pending key is tried when the main one no longer matches `sk_id`). If the Keychain refuses the new key, the new
Recovery Kit is still returned and the UI states that it is the only copy.

### 7.4a Throttling
Failed Master-Password attempts are counted in memory; from the fourth failure on, each attempt first waits
2^(n−3) seconds (max 30 s) in addition to the Argon2id cost. This only slows down someone typing at the keyboard;
it is not a defence against an offline attacker (who needs the Secret Key anyway).

### 7.5 Lock
Drop VMK and all subkeys (`SecureBytes` zeroised, `SymmetricKey` zeroised by CryptoKit), drop the decrypted
item cache and tier-2 plaintext, clear the clipboard if it still holds our last copy, tear down the unlocked UI.

---

## 8. Device-bound secrets: Secure Enclave and Keychain

### 8.1 Secret Key at rest on this Mac

1. If `SecureEnclave.isAvailable`: create a P-256 key in the Secure Enclave with access control
   `[.privateKeyUsage]`, accessibility `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Wrap SK with HPKE
   (`P256_SHA256_AES_GCM_256`, `info = "privatevault/v1/hpke/se-wrap-sk" ‖ vaultID`, `aad = 0x01 ‖ vaultID`).
   Store the record `{version, seKeyDataRepresentation, encapsulatedKey (65 B), ciphertext}` in the Keychain.
   The SE key's data representation is itself encrypted by the Secure Enclave and only this Mac's SEP can use it;
   a copy of the Keychain (Time Machine, disk image, `security dump-keychain`) is useless elsewhere.
2. If no Secure Enclave (VM, old Intel Mac): SK is stored raw in the Keychain (still encrypted by macOS under
   the login password) and the user is shown a one-time warning that the Secret Key's protection then relies on
   the login password. `THREAT_MODEL.md` §scenario 3 describes the difference.
3. Keychain usage: generic-password items, service `com.kostastoulis.privatevault`, account = vaultID,
   `kSecAttrSynchronizable = false`. The app first tries the Data-Protection keychain
   (`kSecUseDataProtectionKeychain = true`); with an ad-hoc signed build macOS returns `errSecMissingEntitlement`
   and the app falls back to the classic login keychain. After the app binary changes (a rebuild), macOS shows
   its standard Keychain dialog once ("PrivateVault wants to use your confidential information…"); choosing
   "Always Allow" records the new build in the item's ACL. If the item cannot be read at all (user denied, item
   deleted, different Mac), the app asks for the Recovery Kit and re-stores the key.
4. If the Keychain is unavailable entirely, the Secret Key is **not** written anywhere else; the user types the
   Recovery Kit at each unlock. (No "helpful" plaintext fallback files.)
5. On a new Mac, after Migration Assistant, after "Erase All Content and Settings" or a SEP reset the SE-wrapped
   blob cannot be opened — the app detects this and asks for the Recovery Kit (Scenario B in `RECOVERY.md`).

### 8.2 Touch ID unlock

- Enabled only while unlocked. Requires `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
- A **second** SE P-256 key is created with `[.privateKeyUsage, .biometryCurrentSet]`. The VMK (with the 32-byte
  zero commitment prefix) is wrapped to it with HPKE (`info = "privatevault/v1/hpke/bio-wrap-vmk" ‖ vaultID`,
  `aad = 0x02 ‖ vaultID ‖ header_sha256`) and stored in the Keychain together with the SE key blob. Binding the
  header checksum means a header modified behind the app's back (salt, KDF parameters, wrapped VMK) makes the
  Touch ID path refuse instead of silently unlocking; after every legitimate header rewrite the blob is re-created
  under a **fresh** Secure-Enclave key (never re-wrapped to a public key read back from the store, which a local
  attacker could have substituted).
- Unlocking: the Secure Enclave refuses to use the key until Touch ID succeeds — the biometric check is enforced
  by the SEP, not by app code. `LAContext` is configured with `localizedFallbackTitle = ""` (no password button:
  the fallback is the Master Password field) and `touchIDAuthenticationAllowableReuseDuration = 0`.
- `.biometryCurrentSet` means adding or removing any fingerprint permanently invalidates the key: the app falls
  back to the Master Password and offers to re-enable Touch ID.
- The Master Password is **never** stored to make Touch ID work. Disabling Touch ID, rotating keys, restoring a
  backup or regenerating the Secret Key deletes the bio blob.
- Touch ID is a convenience unlock: its strength is the Secure Enclave + biometry + this Mac's login session. It
  does not know the password and cannot perform KDF upgrades.

### 8.3 Authentication gates for sensitive actions (policy gates, not crypto boundaries)

| Action | Gate |
|---|---|
| Reveal / copy seed phrase or private key | `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` (Touch ID or login password) + explicit warning; auto-hide after 30 s |
| Show Recovery Kit, change password, rotate keys, regenerate Secret Key, disable Touch ID, export backup, delete vault | Re-enter Master Password |

These gates protect against shoulder-surfing and a briefly unattended unlocked Mac. They are enforced by the app,
which already holds the keys; they are not a cryptographic boundary and `THREAT_MODEL.md` says so.

---

## 9. Encrypted backup (`.privatevault`)

A backup is a JSON document containing **only** material that is already ciphertext or non-secret:

```
{ "format": "privatevault-backup", "version": 1, "createdAt": <i64>,
  "header": { "canonical": b64, "wrappedVMK": b64, "headerSHA256": b64, "skID": b64 },
  "records": [ { "id": b64(16), "cryptoVersion": n, "revision": n, "blob": b64 }, … ],
  "manifest": { "nonce": b64, "ciphertext": b64 } }
```
`manifest` plaintext (binary): `format u8 ‖ header_sha256 32 ‖ count u32be ‖ for each record sorted by id:
recordID 16 ‖ crypto_version u32be ‖ revision u64be ‖ SHA-256(blob) 32`, encrypted with
`AES-256-GCM(key = backupManifestKey, aad = "backup" ‖ version u8 ‖ vaultID ‖ createdAt i64be)`.

Properties: the file never contains the Secret Key, the Master Password, any plaintext field or title; restoring
needs **MP + SK** (typed from the Recovery Kit when the Keychain does not have it); the manifest binds the header
(no header/record splicing between backups), the exact record set (no dropped, added or rolled-back records)
and the creation time. A backup is *authenticated but not fresh*: an attacker can substitute an entire older
legitimate backup — the user sees its `createdAt`. File size and record count are bounded before parsing.
Restore decrypts nothing: it validates, verifies the manifest and every record's AEAD tag into a fresh temporary
database file inside the app container, then atomically renames it into place. No plaintext temporary files
exist at any point.

---

## 10. Process-level protections and honest limits

- **Logging**: `SecureLog` accepts only `StaticString` messages and a small set of non-secret typed values
  (enums, counts, error codes). Strings, models and errors with payloads cannot be logged. A test exercises all
  flows with sentinel secrets and asserts they never appear in the in-memory log sink (every `SecureLog` line
  goes through it before reaching `os.Logger`). Assertions never interpolate values.
- **Crash reports**: macOS `.ips` crash logs contain register/stack snippets and the fault message. We never put
  secrets in fault messages; `RLIMIT_CORE` is set to 0 so no core dump is written. Process memory while unlocked
  is, by definition, readable by a debugger or by malware running as the user — see `THREAT_MODEL.md`.
- **Memory wiping**: keys live in `SecureBytes` (pinned with `mlock`, wiped with `memset_s`) or CryptoKit
  `SymmetricKey` (wiped by CryptoKit). Swift `String`/`Data` values used by the UI are copy-on-write and may be
  copied by the runtime; we cannot guarantee every copy is zeroised. Tier-2 secrets are kept as inner ciphertext
  until revealed to keep this window small. Swap on macOS is encrypted.
- **Clipboard**: copies use `NSPasteboard.prepareForNewContents(with: .currentHostOnly)` (blocks Universal
  Clipboard/Handoff), add the `org.nspasteboard.ConcealedType` and `TransientType` marker types (honoured by
  well-behaved clipboard managers), and are cleared after the configured timeout (default 30 s), on lock, on quit
  and on sleep — only if the pasteboard still holds our item (change count check). The app never reads the
  pasteboard. Limits: a clipboard manager that ignores the marker types, or any process that polls the
  pasteboard, can capture a copied value instantly; macOS offers no API to prevent that.
- **No leaks to disk**: window restoration disabled, no `@SceneStorage`, `UserDefaults` holds only non-sensitive
  settings, autocorrect/spell-check/inline prediction/Writing Tools disabled on secret fields, Spotlight/QuickLook
  not integrated, `.privatevault` declared as opaque data, window sharing blocked while unlocked (optional setting,
  default on), revealed secret views marked `accessibilityProtectedContent`.
- **App integrity**: the bundle is signed ad-hoc with the hardened runtime and App Sandbox (entitlements:
  `app-sandbox`, `files.user-selected.read-write`; nothing else — no network entitlement, so the kernel blocks all
  sockets). Ad-hoc signatures have no certificate chain, so macOS cannot prove the app was not replaced by a
  trojan; `THREAT_MODEL.md` covers this.

---

## 11. What an attacker learns from the files alone

Given `vault.sqlite` (and/or a backup, a Time Machine copy, the whole app container) but **not** the Master
Password, the Secret Key or this unlocked Mac, the attacker obtains:

- format version, vault UUID, KDF algorithm and parameters, salt, wrapped VMK (ciphertext), header hash,
  4-byte Secret-Key identifier, generation counter, creation time of the vault;
- the number of records, each record's random id, revision counter and padded ciphertext size class;
- (Time Machine / container copy) Keychain items containing Secure-Enclave-wrapped blobs usable only on the
  original Mac.

They cannot decrypt a single field, cannot tell which records are wallets, cannot learn a title, cannot test a
Master-Password guess (the KEK needs the Secret Key), and cannot modify records, headers or backups without
detection. This is the design goal stated in the project brief.
