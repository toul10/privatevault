<!--
Outside code contributions are not accepted at this time — please open an issue instead (CONTRIBUTING.md).
This checklist is for the maintainer's own pull requests.
-->

## What and why

## Checklist
- [ ] `Scripts/run-tests.sh` passes
- [ ] `Scripts/secret-scan.sh --all` and `Scripts/audit-network.sh --strict` are clean
- [ ] No network entitlement, networking API, analytics or update check added
- [ ] No real secrets anywhere (code, tests, fixtures, screenshots)
- [ ] Byte-format change? `SECURITY_ARCHITECTURE.md`, migration and golden fixture updated
- [ ] Docs and `CHANGELOG.md` updated
