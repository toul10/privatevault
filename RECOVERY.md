# PrivateVault — Recovery Guide (Version 1)

Plain-language answers to "what do I keep, what can I get back, what is gone for good". `§` references point
to `SECURITY_ARCHITECTURE.md`, the normative spec.

## 1. The three things you keep

| What | Where it lives | Why it matters |
|---|---|---|
| **Master Password (MP)** | Only in your memory; the app never stores it, not even for Touch ID (§8.2). | Half of the key. |
| **Secret Key (SK) — the Recovery Kit** | On this Mac: in the Keychain, wrapped by the Secure Enclave, usable only here (§8.1). On paper: the Recovery Kit, `PV1-XXXXX-XXXXX-…`, 11 groups of 5 characters (§2.4). | The other half. Without it nobody can even *start* guessing the password. |
| **Encrypted backups (`.privatevault`)** | Wherever you put them (USB, second disk, cloud). Only ciphertext — no password, no Secret Key, no titles (§9). | The only way back if this Mac is lost or wiped. |

The rule behind every scenario: **the vault opens only with MP + SK, and the data exists only in the vault
file or in a backup.** No third factor, no hidden copy, no exception.

About the kit: shown once at creation (you must re-type one group); shown again later only after re-entering
the Master Password. It carries a 4-byte `sk_id` so you can match kit and vault. Typing is forgiving (lower
case, `I`/`L` for `1`, `O` for `0`, missing hyphens) and three check characters catch typos before any unlock
attempt. The kit is as sensitive as the vault: alone it opens nothing, but whoever holds it can try passwords
offline — that is why the password must be strong (§2.2).

## 2. Scenarios

### A — you remember the Master Password and still have this Mac
Nothing to recover. Unlock with the password (or Touch ID). If the app ever cannot read the Secret Key from
the Keychain silently, it asks for the Recovery Kit once and stores it again (§8.1.3). Keep backing up.

### B — you remember the Master Password, the Mac is lost, you have the Recovery Kit and a backup
**Fully recoverable.** On a new Mac: install PrivateVault → *Restore from backup* → pick the file → enter the
Master Password and type the Recovery Kit. The app verifies the manifest and every record, writes a fresh vault,
stores the Secret Key wrapped to the new Mac's Secure Enclave and asks you to re-enable Touch ID. Limits: you
get the data **as of the backup's date** (the app shows `createdAt`); anything added later is gone. A backup
opens with the password and Secret Key valid **when it was made** (section 8).

### C — you lost the Master Password (you have the Mac and the Recovery Kit)
**Not recoverable by design.** The Recovery Kit is the second half of the key, not a password reset. What is
left:
- If you remember *most* of it, keep trying variants at the unlock screen; each attempt costs about a second
  of Argon2id work, all local.
- If Touch ID is enabled and still works, it still unlocks the vault (it holds the VMK, not the password,
  §8.2). Use that session to **move your data out** — reveal and copy every item somewhere safe. Touch ID
  cannot change the password, export a backup or show the Recovery Kit (those require the Master Password,
  §8.3), and it dies the moment a fingerprint is added or removed. A closing window, not recovery.
- Otherwise the vault is gone (section 9).

### D — you lost the Recovery Kit (you have the Mac and the password)
**Recoverable — act today.** The Secret Key is still in this Mac's Keychain, so the vault works, but you are
one hardware failure away from total loss. While unlocked, choose one:
- *Show Recovery Kit* (re-enter the Master Password) and print a new copy — enough if the kit was merely
  destroyed.
- *Regenerate Secret Key* (re-enter the Master Password) — if the kit may be in someone else's hands. The app
  creates a new Secret Key, rotates all keys, re-encrypts every record (§7.4) and shows a new kit. The old kit
  becomes useless to whoever has it — **and old backups now need the old kit** (section 8). Back up at once.

### E — you lost both
**Not recoverable.** If Touch ID still works, use the salvage step from Scenario C — your last chance.
Otherwise the vault file is permanent ciphertext to you, to the author and to everyone else.

## 3. New Mac, Migration Assistant, "Erase All Content and Settings", Time Machine

The Secret Key on this Mac is wrapped by a Secure-Enclave key that only **this** Mac's Secure Enclave can use.
After Migration Assistant, a Time Machine restore onto other hardware, "Erase All Content and Settings" or a
Secure-Enclave reset, that blob is unusable (§8.1.5). The app detects it, asks for the Recovery Kit, unlocks with
your password and stores the key again under the new Secure Enclave. Touch ID must be re-enabled (its key is
gone too). If the vault file itself did not come along (erase without restore), you also need a backup — that
is Scenario B. After a legitimate Time Machine restore the app may warn that the vault is older than the last
one it saw; acknowledge it (§5.3).

## 4. Fingerprint changed — Touch ID stops working

The Touch ID key is bound to the *current* fingerprint set; adding or removing a finger invalidates it for good
(§8.2). Unlock with the Master Password and re-enable Touch ID in settings. No data is affected.

## 5. You forgot the password — but the vault is open right now

Act before it locks. Changing the password requires the current one (§7.3, §8.3), so try your candidates in
the *Change Master Password* dialog — it verifies the current password, a wrong guess only costs time. If one
works, change the password **now** to one you will keep. If none works, this session is your last chance to
read the data: reveal and copy your items out before the vault locks (auto-lock included). Do not quit the app.

## 6. Keychain item deleted or unreadable

If the Secret-Key item is gone or unreadable (deleted in Keychain Access, a different build of the app, a denied
prompt) the app asks for the Recovery Kit and stores it again — nothing is lost. If the Touch ID item is gone,
re-enable Touch ID. If the Keychain is unavailable entirely, the app never writes the key anywhere else: you
type the Recovery Kit at each unlock (§8.1.4). No kit **and** no Keychain item = Secret Key gone on every copy:
not recoverable (section 9).

## 7. Restoring a backup

You need the `.privatevault` file, the **Master Password** and the **Secret Key** (from the Keychain on the same
Mac, otherwise typed from the Recovery Kit). *Restore from backup* → pick the file → the app checks size, format
and record count → enter the password (and the kit if asked) → the app verifies the encrypted manifest and every
record's authentication tag into a temporary database in its own container, then atomically swaps it into place
(§9). Nothing is decrypted to disk. Restore **replaces** the current vault — if that holds newer data, back it up
first. Check the shown creation date: a backup is authenticated but not fresh (an older genuine file could have
been substituted). Touch ID must be re-enabled afterwards.

## 8. Password change, key rotation, "Regenerate Secret Key" — effect on old backups

- **Change Master Password** (default): only the header is re-wrapped, records untouched (§7.3). Old backups
  still open — with the **old** password and the same Secret Key.
- **Key rotation** (optional on password change) and **Regenerate Secret Key** (always rotates): every record
  is re-encrypted under a new Vault Master Key (§7.4). Old backups open only with the password *and* the
  Recovery Kit valid when they were made. Destroy the old kit and those backups become unreadable forever.
- Rule: after any of these, **make a new backup immediately**; keep old kits labelled until the backups that
  need them are deleted.

## 9. What is NOT recoverable — and who cannot help

| Loss | Result |
|---|---|
| Master Password, vault locked, no working Touch ID | Everything. The Recovery Kit does not substitute. |
| Secret Key on all copies (no Keychain item, no kit) | Everything. The password does not substitute. |
| Old backups whose password/kit of the time is gone | Those backups. |
| Data added after the last backup, Mac lost | That data. |
| Touch ID enrolment | Nothing — always re-creatable. |

There is **no developer backdoor, no universal recovery key, no recovery service, no hidden copy**. Nobody —
the author included — can open a vault, reset a password or replace a lost kit without MP + SK; the design makes
it impossible, not merely forbidden (§0, §11). Anyone who claims otherwise is a scammer.

## 10. Do this today

1. **Print the Recovery Kit** (or copy it by hand in block capitals from the alphabet
   `0123456789ABCDEFGHJKMNPQRSTVWXYZ`). Make two copies.
2. **Verify it by re-typing**: the app makes you re-type one group at creation; check every other group
   against the screen character by character (or re-open *Show Recovery Kit* with the Master Password and
   compare). A typo found today costs nothing; found in Scenario B it costs everything.
3. **Make the first encrypted backup** — and a new one after every meaningful change, and always after a
   password change, rotation or Secret Key regeneration.
4. **Store separately**: kit and backup away from the Mac and from each other; no photo of the kit in a cloud
   photo library; never the password written next to the kit.
5. **Memorise the Master Password**; if you must write it down, keep it apart from the kit.
