# Contributing to PrivateVault

Thank you for wanting to help. PrivateVault is a security product with a single maintainer, so contributions work a
little differently from a typical open-source project.

## Welcome right now

- **Security reports** — privately, as described in `SECURITY.md`. Never in a public issue.
- **Bug reports** — open an issue with the *Bug report* form.
- **Feature ideas** — open an issue with the *Feature request* form.
- **Documentation fixes** — typos and unclear wording: open an issue quoting the passage.

## Pull requests: not accepted for now

Code contributions are not merged at this time, for two reasons:

1. Every line of a password manager must be reviewed with the same care as its cryptography; a malicious or
   subtly wrong change is a real attack on users.
2. The maintainer distributes PrivateVault commercially, so outside code would also need a contributor licence
   agreement.

If you have a fix, open an issue that describes it. It may be re-implemented by the maintainer, with credit.

## Never share real secrets

Issues, logs, screenshots and attachments are public. Never include real passwords, seed phrases, private keys,
API keys, vault files (`vault.sqlite`), backups (`.privatevault`) or Recovery Kits — not even old or "test" ones.
Reproduce with a new vault and obviously fake data.

## Working on your own copy

The license (`LICENSE.md`, FSL-1.1-ALv2) lets you read, build, modify and use the code for any purpose except a
competing commercial product. To build it yourself:

```
git config core.hooksPath .githooks   # pre-commit + pre-push secret scans
Scripts/run-tests.sh                  # the full test suite; Command Line Tools are enough
Scripts/build-app.sh                  # "PrivateVault Dev": own container + Keychain items, never your real vault
```

House rules (they apply to the maintainer too):

- **No network.** Never add a network entitlement, a networking API, analytics, a crash reporter or an update
  checker (`Scripts/audit-network.sh --strict` must stay clean).
- **Never log, print, serialise or persist a secret.** Use `Secret<T>` and `SecureBytes`; secrets reach the
  pasteboard only through `ClipboardPolicy`.
- **Fake test data only.** No real-looking mnemonics, keys or passwords in tests or fixtures.
- **Byte formats are frozen.** Any change to the header, the record envelope or the backup format needs a spec
  update in `SECURITY_ARCHITECTURE.md`, a migration, and an updated golden-fixture test.
- **Crypto changes** need known-answer tests and an entry in `SECURITY_AUDIT.md`.
- **No new third-party dependencies** (`DEPENDENCY_SECURITY.md`).
- **Docs stay true.** Behaviour changes update the README, the threat model and `CHANGELOG.md`.
