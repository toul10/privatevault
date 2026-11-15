# Security Policy

PrivateVault stores the most sensitive data people have. Security reports are the most valuable contribution you
can make, and they are handled privately.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:

1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability**.

Direct link: <https://github.com/toul10/privatevault/security/advisories/new>

Please include:

- the affected version (PrivateVault → About PrivateVault) and your macOS version and Mac model;
- what an attacker needs — for example "a copy of the vault file", "a local user account", "the unlocked app";
- the steps to reproduce, and the impact.

**Never include real secrets.** No real passwords, seed phrases, private keys, API keys, vault files
(`vault.sqlite`), backups (`.privatevault`) or Recovery Kits — not even old ones. Reproduce with a new test vault
and obviously fake data.

## What to expect

- Acknowledgement within 7 days.
- An assessment within 30 days and, for confirmed issues, a fix plan. Cryptographic issues can take longer; you
  will be kept informed.
- Credit in the advisory and the release notes, unless you prefer to stay anonymous.
- Coordinated disclosure: please allow up to 90 days, or until a fixed version is released, before publishing.

## Supported versions

| Version | Supported |
|---|---|
| 1.x — latest release | ✅ |
| Older releases, modified or self-signed builds | ❌ |

## Scope

**In scope** — anything that breaks the guarantees in `SECURITY_ARCHITECTURE.md` and `THREAT_MODEL.md`, for example:

- recovering any secret, title or other metadata from a vault file, backup or Time Machine copy without both the
  Master Password and the Secret Key;
- weaknesses in key derivation, key wrapping, the record envelope, the backup format or the state MAC (deletion,
  splicing or rollback going undetected);
- secrets written to logs, preferences, window titles, Spotlight, swap or core dumps, or left on the pasteboard
  contrary to the documented policy;
- bypassing the Touch ID / login-password gates (Reveal, copy) or the auto-lock;
- any way for the app to make a network connection;
- weaknesses in the build, signing or release process (supply chain).

**Out of scope** — the documented limits in `THREAT_MODEL.md` §4, including:

- malware running in your logged-in session, or a person using the Mac, while the vault is unlocked;
- kernel-level keyloggers, or processes you granted Screen Recording, Accessibility or Input Monitoring;
- a weak login password without FileVault;
- clipboard managers that ignore the concealed/transient markers;
- a forgotten Master Password, or a lost Secret Key with no Recovery Kit (unrecoverable by design);
- coercion, hardware implants and side channels on a compromised host;
- vulnerabilities in macOS itself — please report those to Apple.

## Good-faith research

If you act in good faith, follow this policy, test only on your own devices with your own test vaults, and give
reasonable time for a fix, your research is welcome and will not be treated as a violation of the license.
