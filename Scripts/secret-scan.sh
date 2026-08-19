#!/bin/zsh
# Lightweight secret scan used by the pre-commit hook and the final audit.
# Scans STAGED content (default) or all tracked files (--all) for things that must never be committed.
# Exit 1 on any hit. Frozen test fixtures with FAKE credentials are allow-listed below.
set -uo pipefail
cd "$(dirname "$0")/.."
mode="${1:-staged}"
if [[ "$mode" == "--all" ]]; then
  files=$(git ls-files)
  content() { cat -- "$1" 2>/dev/null; }
else
  files=$(git diff --cached --name-only --diff-filter=ACMRT)
  content() { git show ":$1" 2>/dev/null; }          # the staged blob, not the working tree
fi
[[ -z "$files" ]] && exit 0
rc=0
for f in ${(f)files}; do
  [[ "$f" == Tests/VaultCoreTests/Fixtures/golden-v1.* ]] && continue   # frozen format fixture with FAKE credentials
  case "$f" in
    *.sqlite|*.sqlite-wal|*.sqlite-shm|*.db|*.privatevault|*.p12|*.pem|*.key|*.mobileprovision)
      echo "BLOCKED: forbidden file type staged: $f"; rc=1;;
  esac
done
# Content patterns (case-insensitive where lookalike forms are accepted by the app)
patterns=(
  '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'                       # AWS access key id
  'sk_live_[0-9a-zA-Z]{24,}'               # Stripe live secret
  'xox[baprs]-[0-9A-Za-z-]{10,}'           # Slack token
  'ghp_[0-9A-Za-z]{36}'                    # GitHub PAT
  'xprv[0-9A-Za-z]{100,}'                  # BIP32 extended private key
)
# PrivateVault Recovery Kit: prefix optional, separators optional, any case, I/L/O lookalikes (as RecoveryKit.decode accepts)
kit_pattern='(PV1[- ]?)?([0-9A-HJKMNP-TV-ZILO]{5}[- ]?){10}[0-9A-HJKMNP-TV-ZILO]{5}'
for f in ${(f)files}; do
  [[ "$f" == Tests/VaultCoreTests/Fixtures/* ]] && continue
  blob=$(content "$f") || continue
  [[ -z "$blob" ]] && continue
  # skip binaries (contain NUL bytes)
  if printf '%s' "$blob" | perl -0777 -ne 'exit(index($_, "\0") >= 0 ? 0 : 1)'; then continue; fi
  for p in "${patterns[@]}"; do
    if printf '%s\n' "$blob" | grep -E -n -- "$p" >/dev/null 2>&1; then
      echo "BLOCKED: pattern '$p' found in $f:"; printf '%s\n' "$blob" | grep -E -n -- "$p" | head -3
      rc=1
    fi
  done
  if printf '%s\n' "$blob" | grep -i -E -n -- "$kit_pattern" >/dev/null 2>&1; then
    echo "BLOCKED: Recovery-Kit-looking string in $f:"; printf '%s\n' "$blob" | grep -i -E -n -- "$kit_pattern" | head -3 | cut -c1-120
    rc=1
  fi
  # 64-hex private-key-looking strings outside tests/docs
  if [[ "$f" != Tests/* && "$f" != *.md ]]; then
    if printf '%s\n' "$blob" | grep -i -E -n -- '(private[_ -]?key|seed|mnemonic)[^\n]{0,40}[0-9a-f]{64}' >/dev/null 2>&1; then
      echo "BLOCKED: 64-hex value near private-key/seed wording in $f"; rc=1
    fi
  fi
done
exit $rc
