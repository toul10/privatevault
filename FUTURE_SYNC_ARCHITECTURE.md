# PrivateVault — Future Sync Architecture (proposal, **not built in Version 1**)

**Status:** design proposal. Nothing here exists in the V1 code; the V1 app has no network entitlement and
ships exactly what `SECURITY_ARCHITECTURE.md` describes. This document explains how the encrypted vault could
later be kept in step between a MacBook, a Mac Studio and an iPhone through a server the owner runs himself —
and why the V1 design already has the shapes needed to do that safely. Bare `§n` references point to
`SECURITY_ARCHITECTURE.md`; sections of this document are cited as "§n below".

---

## 0. The idea in one paragraph

The sync server is treated like a `.privatevault` backup file lying on a USB stick: it holds only ciphertext and
non-secret bookkeeping, and it is assumed to be **malicious** (it may lie, withhold, replay or reorder). It never
receives anything that could decrypt the vault. Every device holds its own copy of the Secret Key (transferred
device-to-device, wrapped to that device's Secure Enclave), asks the owner for the Master Password locally, and
derives the VMK and every subkey locally (spec §2). The server only stores encrypted rows, hands them out by
cursor, remembers which devices exist, and refuses to go backwards.

---

## 1. Goals and non-goals

**Goals**

1. Same zero-knowledge property as a backup: the server learns no plaintext, no title, no Master Password, no
   Secret Key, no VMK, and cannot test a single password guess (§2.1 of the spec still holds).
2. Multi-device, eventually consistent, **no silent data loss**: conflicts become visible conflict copies.
3. Device enrollment without any secret ever passing through the server in a form the server can read.
4. Device revocation with a real cryptographic effect, not just "the server forgets the device".
5. *Detection* of server misbehaviour (replay, fork, withholding) with clear warnings to the owner.
6. Offline first: a device is always fully usable without the server; sync is a background convenience.

**Non-goals (explicitly out of scope)**

- Sharing with other people, a web interface, server-side search or any server-side decryption.
- Hiding *metadata* from the server: record count, random ids, revisions, size classes, sync times, device count.
- Protecting against a **compromised enrolled device** — it has the Secret Key and sees the Master Password when
  typed; that is a full compromise, as on V1's single Mac.
- Forcing a revoked device to forget data it decrypted before revocation.
- Blockchain signing/RPC/derivation, a hosted service run by someone else, plaintext export.

---

## 2. What the server stores, and what it must never receive

| Server stores (all non-secret or ciphertext) | Notes |
|---|---|
| `records(id 16 B, crypto_version, revision, blob, server_seq)` | exactly the V1 row (§4.1) plus an append-only server sequence number |
| `vault_header` blob: canonical bytes ‖ `wrapped_vmk` ‖ `header_sha256` ‖ `sk_id`, plus `generation` as a column | the same material as a backup's `header` object (spec §9); `generation` lets the server refuse downgrades |
| device roster: `device_id`, Ed25519 public key, P-256 enrollment public key, enrolled-by, enrollment signature, status | public keys only; display names travel **inside** ciphertext |
| signed device manifests (§8 below) | Ed25519-signed by each device; opaque to the server |
| per-device sync cursor (last acknowledged `server_seq`) | bookkeeping |

| The server must **never** receive | Why |
|---|---|
| Master Password, MPK, Secret Key, SKK, KEK, VMK, any HKDF subkey, per-record keys, tier-2 plaintext | anything that decrypts |
| any plaintext field, item kind, title, tag, timestamp, website, username | everything is inside the record envelope (§4.1) |
| the Recovery Kit string, Touch ID / Face ID blobs, Secure Enclave key blobs | device-bound secrets (§8) |
| any password-derived authentication value | authentication is per-device keys only (§7 below) |

The "what an attacker learns from the files" list in §11 of the spec is exactly what the server learns, plus
sync timing, IP addresses, device count and enrollment/rotation events. That is the honest metadata cost.

---

## 3. How the V1 design already prepares for this

| V1 property (spec §) | What it buys sync |
|---|---|
| random 16-byte record `id` (§4.1) | globally unique address with no ordering or content leak; two devices never collide |
| `revision` inside the AEAD AAD (§4.2) | the server cannot relabel a ciphertext as a newer or older version; per-record conflict resolution has an authenticated counter |
| `generation` in the canonical header (§3.1) and in the Touch ID AAD (§8.2) | "header only moves forward" is checkable by every device |
| `state_mac` over `(id, revision)` list (§5.3) | each device keeps detecting local rollback; the same preimage, hashed, is what devices sign for each other |
| canonical byte encodings with golden tests (§3.1, §4.2) | every device computes identical AAD/MAC bytes; the wire format is already frozen |
| HPKE with Secure-Enclave P-256 keys (§1, §8.1) | the enrollment wrap is the same primitive as the SK wrap, with a new label |
| reserved HKDF label `privatevault/v1/sync-auth` (§2) | proposed use: HMAC key for the device roster, so only an unlocked device can vouch for a new device |
| `Secret<T>` refuses encoding outside the vault codec (§6) | a transport layer physically cannot serialise plaintext by accident |
| key rotation §7.4 + Secret Key regeneration | the revocation mechanism already exists |

---

## 4. Sync protocol

### 4.1 Overview

```
  MacBook ──push {id, crypto_version, revision, blob}──▶ ┌──────────────────────────┐
          ◀──pull changes since cursor ───────────────── │  owner's server (untrusted) │
  Mac Studio ◀───────────────────────────────────────────│  records / header / roster │
  iPhone    ◀───────────────────────────────────────────│  manifests / cursors       │
                                                          └──────────────────────────┘
  Only EncryptedRecord / EncryptedHeader / signed manifests cross this line. Never keys, never plaintext.
```

Each device keeps its V1 database unchanged and adds a `sync_state` table: per record the `base_revision` last
confirmed by the server and a `pending` flag; the device's cursor; the trusted roster. All of it is non-secret.

### 4.2 Push / pull of ciphertext by revision

- **Edit locally:** `revision = max(local revision, last server revision) + 1`, re-encrypt (fresh nonce, new AAD),
  update `state_mac` in the same transaction — exactly V1 — and mark `pending`.
- **Push:** send `(id, crypto_version, revision, blob)` with the expected server revision. The server applies a
  **compare-and-swap**: it accepts only `revision == stored + 1` (or a new id); otherwise it rejects and returns
  the current row.
- **Pull:** fetch rows with `server_seq > cursor`, the header if its `generation` changed, and the other devices'
  latest manifests. Each pulled record is opened with AAD `"record" ‖ vaultID ‖ id ‖ crypto_version ‖ revision`
  — a server that altered any field fails the tag. A pulled `revision` must be **strictly greater** than the local
  one for that id, otherwise it is ignored and counted as a replay. Apply, recompute `state_mac`, advance the
  cursor — one transaction.
- **Last-writer-wins with conflict copies:** if a pull brings revision `r > base_revision` for a record with a
  local `pending` edit, the server's version becomes the main record and the local version is saved as a **new
  record** (new random id) whose encrypted JSON carries `conflictOf: id, device, time`. Nothing is overwritten
  silently; the owner merges by hand.
- **Tombstones as encrypted records:** deletion writes a new revision whose plaintext is `kind = tombstone`,
  padded to the **same size class** as the version it replaces (an extension of the §4.3 padding, which in V1 is
  driven by the plaintext length alone), so the server cannot tell a deletion from an edit. Devices delete locally when they pull a tombstone; the row may be garbage-collected once every enrolled
  device's cursor has passed it.

### 4.3 Header sync: forward only

The header (password change §7.3, KDF upgrade §2.3, rotation §7.4) is pushed with its `generation`. The server
rejects a header whose generation is not greater than the stored one; every device **also** enforces this locally
and against the generation mirrored in its Keychain item (§5.3). A device never applies a lower generation,
whatever the server says.

After a **rotation** on device A (new VMK, every record re-encrypted with `revision + 1`, new header, one
transaction) device B pulls header + all records as one batch and applies them in one transaction; B's Touch ID /
Face ID blob no longer matches (its `aad` contains the generation, §8.2) and is deleted; B asks for the Master
Password, derives the new KEK with its Secret Key, opens the new `wrapped_VMK`, re-enables biometrics. If the
Secret Key was regenerated too (§6 below) B's KEK is wrong, the open fails with the uniform `authenticationFailed`, and
B is told "the Secret Key was regenerated on another device — re-enrol this device or type the new Recovery Kit".

---

## 5. Device enrollment

New device **N** (say the iPhone) must end up with the **Secret Key** — and only that. It still has to ask the
owner for the Master Password, so a lost phone, or an enrollment the owner approved by mistake, yields SK without
the vault (§2.1). The VMK is **never** transferred.

```
 N: new device (nothing yet)                          T: trusted device, unlocked, Master Password re-entered
 ── generate device_id (16 B random), Ed25519 identity key,
    P-256 enrollment key in the Secure Enclave ──
 1. req = {v, device_id_N, pkN_enc (P-256), pkN_sig (Ed25519)}   ──▶   (QR shown by N, or relayed via server)
 2.                                            ◀──  commit = SHA-256("privatevault/v1/enroll-commit" ‖ nonce_T ‖ pkT_sig ‖ req)
 3. nonce_N (16 B)                             ──▶
 4.                                            ◀──  open = {device_id_T, pkT_sig, nonce_T}   N checks commit
 5. SAS = 6 decimal digits of SHA-256("privatevault/v1/enroll-sas" ‖ req ‖ pkT_sig ‖ nonce_N ‖ nonce_T)
    → shown on BOTH screens; the owner compares and confirms on T. Mismatch = abort, nothing sent.
 6.                                            ◀──  package = HPKE.seal(to pkN_enc, suite P256_SHA256_AES_GCM_256,
                                                     info = "privatevault/v1/hpke/enroll-sk" ‖ device_id_N,
                                                     aad  = 0x03 ‖ vaultID ‖ device_id_N ‖ SHA-256(transcript 1–4))
                                                     plaintext = SK ‖ vaultID ‖ sk_id ‖ server URL ‖ server key pin
 7. N opens the package inside its Secure Enclave key, verifies sk_id, stores SK exactly as §8.1,
    asks for the Master Password, pulls header + records, derives everything locally.
 8. T signs an enrollment certificate Sig_T(vaultID ‖ device_id_N ‖ pkN_enc ‖ pkN_sig ‖ device_id_T ‖ time),
    adds N to the roster, re-MACs the roster with HKDF(VMK, "privatevault/v1/sync-auth"), uploads it.
```

- **Why the commit step:** a 6-digit SAS is only ~20 bits. If messages pass through the (malicious) server, a
  man-in-the-middle who sees one side's nonce before choosing its own could grind 2^20 hashes to make both screens
  agree. With T committed to `nonce_T` before seeing `nonce_N`, the attacker gets one chance in a million, and
  every failure is a visible mismatch (the Bluetooth/ZRTP numeric-comparison pattern).
- **Transports:** over **QR** (MacBook camera reading the Mac Studio's or iPhone's screen) N's QR is messages
  1+3 and T's QR is 2+4; the package (6) is a final QR or is relayed through the server addressed to `device_id_N`
  (HPKE ciphertext, harmless in transit). Over the **server relay** (no camera) the four messages are opaque
  blobs addressed by device id, rate-limited, expiring after 10 minutes.
- **Why P-256 and not X25519:** CryptoKit's HPKE offers both; P-256 is kept because the Secure Enclave on every
  Apple device can hold the recipient key, so the wrapped Secret Key opens only inside that device's SEP.
- **Gate:** "Enrol a device" joins the "re-enter Master Password" row of §8.3.
- **Trust root:** the first device's Ed25519 key is the root. A device stores the roster locally only after each
  entry's certificate chains to a device it already trusts **and** the roster MAC verifies under the VMK-derived
  key. A device that merely *appears* on the server is ignored and flagged.

---

## 6. Device revocation

Revocation = **"Regenerate Secret Key"** (mandatory rotation, spec §7.4) performed on a trusted device while
the owner re-enters the Master Password:

`SK' ← random; VMK' ← random; re-encrypt every record; new header (generation + 1, new sk_id); new Recovery Kit;
roster entry for the revoked device marked revoked and re-MACed; push everything.`

The revoked device still holds the old SK and possibly the old VMK, but every record on the server is now
encrypted under keys derived from VMK', and VMK' is wrapped under a KEK that needs SK'. It cannot decrypt a single
new byte and cannot re-enrol (certificate revoked, server credential disabled). The remaining trusted devices need
SK': they re-enrol (§5 below, device-to-device) or the owner types the new Recovery Kit. **Honest limit:** data the
revoked device already decrypted stays with it; remote wipe cannot be guaranteed — wipe or reset that device too.

---

## 7. Server authentication and transport

- **TLS 1.3 with certificate pinning** to the owner's own server: the pin (SHA-256 of the server's public key)
  is delivered inside the enrollment package, never fetched; pin rotation is itself a signed roster change.
- **Per-device Ed25519 challenge-response:** the server sends a 32-byte nonce; the device returns
  `Sig_device("privatevault/v1/sync-challenge" ‖ vaultID ‖ device_id ‖ nonce ‖ server pin ‖ time)`; the server
  verifies against the enrolled public key and issues a short-lived session token. **Nothing derived from the
  Master Password or Secret Key is ever used for authentication.** A stolen server credential yields ciphertext only.
- The Ed25519 key is a software key in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  `kSecAttrSynchronizable = false`); a Secure-Enclave P-256 signing key would work identically if hardware
  binding is preferred (open question).
- **Entitlement change:** a sync-capable build needs `com.apple.security.network.client`. V1's guarantee "the
  kernel blocks all sockets" (§10) then becomes "the app connects only to the pinned host" — enforced by app code.
  That is a real weakening and is why the V1 build stays network-free.

---

## 8. Malicious server: attacks and mitigations

| Attack | Mitigation | Residual |
|---|---|---|
| **Replay** an old authentic `(id, revision, blob)` | revision in AAD; device accepts only strictly higher revisions per id; manifests list the `(id, revision)` set | none for decryption; a replayed row is logged as suspicious |
| **Header downgrade** (old password's header) | generation in canonical bytes; device and Keychain mirror refuse lower generation; after rotation old headers do not open new records | none |
| **Drop a deletion / drop records** | tombstones are ordinary records with revisions; signed manifests carry `SHA-256(sorted (id ‖ revision))` — the `state_mac` preimage — so other devices see what each device has confirmed | detected after the next sync of another device |
| **Fork** (show MacBook one history, iPhone another) | each device publishes a signed manifest `{vaultID, device_id, generation, cursor, set-hash, counter}`; a device compares the server's view with every other device's latest manifest; a set-hash that is not a prefix-consistent successor = "server served a divergent view" | detected, not prevented |
| **Withholding** (freeze a device on an old snapshot) | manifest counters and cursors must only increase; a device whose peers' manifests stop advancing shows "last confirmed by MacBook at …"; each device displays a short **sync fingerprint** (digits of the set-hash + generation) the owner can compare by eye | a perfectly consistent stale snapshot to a device that never meets another device is undetectable without that out-of-band comparison |
| **Fake device in the roster** | enrollment certificates chain to a trusted device; roster MAC under the VMK-derived `sync-auth` key; SAS at enrollment | none |
| **Tamper with ciphertext** | AEAD tag with full AAD | none |
| **Decrypt / guess passwords** | server never has SK or VMK | none |

---

## 9. iPhone considerations

- **Keychain:** iOS has only the Data-Protection keychain; SK is stored HPKE-wrapped to an iPhone Secure Enclave
  P-256 key, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable = false` (**never** iCloud
  Keychain). A new phone restored from backup does not get the item → re-enrol or type the Recovery Kit (as on a
  new Mac, §8.1 point 5).
- **Face ID** replaces Touch ID with the same `.biometryCurrentSet` SEP-enforced HPKE blob (§8.2).
- **Argon2id memory:** header parameters are shared by all devices; a phone may not survive a 1 GiB `m` in the
  foreground. A vault that enables sync should cap `m` (e.g. 256 MiB) — open question.
- **UI hygiene:** lock on background, blank the app-switcher snapshot, `UIPasteboard` items `localOnly` with an
  expiry, no Spotlight/Siri indexing.
- **Practical:** an iOS app needs Xcode and an Apple Developer signing identity; neither exists on this machine
  today (Command Line Tools only, ad-hoc signing).

---

## 10. What must be added to the code

All of this lives in a new module (say `VaultSync`) that depends on `VaultCore` but **never imports** the item
model. Type-level rule, enforced by a lint test: no `SyncTransport` signature mentions `VaultItem`, `Secret<T>`,
`SymmetricKey` or `SecureBytes` — the transport can only ever see `EncryptedRecord` values.

```swift
/// The only shape that crosses the network. Opaque to the transport.
public struct EncryptedRecord: Sendable, Equatable {
    public let id: RecordID          // 16 random bytes (§4.1)
    public let cryptoVersion: UInt32
    public let revision: UInt64
    public let blob: Data            // [0x01][nonce][ciphertext][tag], untouched
}
public struct EncryptedHeader: Sendable { canonical: Data; wrappedVMK: Data; headerSHA256: Data; skID: Data; generation: UInt32 }
public struct SyncCursor: Sendable, Hashable { let value: UInt64 }   // server-assigned, opaque

public protocol SyncTransport: Sendable {
    func pull(since: SyncCursor) async throws -> PullBatch      // header?, [EncryptedRecord], [SignedDeviceManifest], next cursor
    func push(_ records: [EncryptedRecord], expecting: [RecordID: UInt64]) async throws -> PushResult  // compare-and-swap
    func pushHeader(_ header: EncryptedHeader) async throws     // server rejects non-increasing generation
    func publish(_ manifest: SignedDeviceManifest) async throws
    func fetchRoster() async throws -> SignedDeviceRoster
    func relayEnrollment(_ message: Data, to: DeviceID) async throws
}

public protocol DeviceKeyStore: Sendable {
    var deviceID: DeviceID { get }
    func signingPublicKey() throws -> Curve25519.Signing.PublicKey
    func sign(_ message: Data) throws -> Data                     // Ed25519; private key never leaves the store
    func enrollmentPublicKey() throws -> P256.KeyAgreement.PublicKey
    func openEnrollment(_ sealed: HPKESealedBox, info: Data, aad: Data) throws -> SecureBytes  // SE-resident recipient
    func trustedRoster() throws -> SignedDeviceRoster
    func storeTrustedRoster(_ roster: SignedDeviceRoster) throws
}
```

Also needed: a `SyncEngine` (reconciliation, conflict copies, tombstones, manifest checks) unit-tested against an
in-memory fake transport **and** a deliberately malicious fake (replays, withholding, forks, fake roster entries);
`VaultItem.Kind.tombstone` and `conflictOf` metadata; a `sync_state` table and migration; the new versioned labels
(`enroll-commit`, `enroll-sas`, `hpke/enroll-sk` with aad purpose `0x03`, `sync-challenge`, `device-manifest`)
next to the V1 labels (`KDFLabel` in `Sources/VaultCore/Crypto/KeyDerivation.swift`) with golden tests; a Keychain/SE-backed `DeviceKeyStore` plus fakes. Two additions to the
§1 primitive table, both Apple-only (still no third-party crypto): Ed25519 via CryptoKit `Curve25519.Signing`,
and TLS with pinning via `URLSession`.

---

## 11. Open questions

1. Ed25519 software key vs Secure-Enclave P-256 signing key for device identity (hardware binding vs simplicity).
2. Relay-through-server enrollment vs QR-only (the Mac Studio has no camera).
3. Argon2id `m` cap for vaults that enable sync, so the iPhone can unlock.
4. Tombstone retention: garbage-collect after all devices acknowledge, or keep forever (cheap, simpler).
5. Should a conflict copy also be created when the server rejects a push (CAS failure) before the device pulled?
6. CloudKit (private database, opaque blobs) as an alternative transport with the same trust model — removes the
   owner's server but adds Apple's account and needs a paid developer identity.
7. What the app shows when manifests disagree: a warning banner, or refuse to push until the owner acknowledges?
8. Whether the sync-capable build is a separate product from the network-free V1 build, or a runtime switch.
