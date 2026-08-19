#!/bin/zsh
# Lightweight secret scan used by the pre-commit hook and the final audit.
# Scans staged files (default) or all tracked files (--all) for things that must never be committed.
# Exit 1 on any hit. Test fixtures must use obviously fake values and may be allow-listed below.
set -uo pipefail
cd "$(dirname "$0")/.."
mode="${1:-staged}"
if [[ "$mode" == "--all" ]]; then
  files=$(git ls-files)
else
  files=$(git diff --cached --name-only --diff-filter=ACM)
fi
[[ -z "$files" ]] && exit 0
rc=0
# Forbidden file types
for f in ${(f)files}; do
  case "$f" in
    *.sqlite|*.sqlite-wal|*.sqlite-shm|*.db|*.privatevault|*.p12|*.pem|*.key|*.mobileprovision)
      echo "BLOCKED: forbidden file type staged: $f"; rc=1;;
  esac
done
# Content patterns (binary files skipped by grep -I)
patterns=(
  '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'                       # AWS access key id
  'sk_live_[0-9a-zA-Z]{24,}'               # Stripe live secret
  'xox[baprs]-[0-9A-Za-z-]{10,}'           # Slack token
  'ghp_[0-9A-Za-z]{36}'                    # GitHub PAT
  'PV1-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}'   # PrivateVault Recovery Kit
  'xprv[0-9A-Za-z]{100,}'                  # BIP32 extended private key
)
for f in ${(f)files}; do
  [[ -f "$f" ]] || continue
  for p in "${patterns[@]}"; do
    if grep -I -E -n -- "$p" "$f" >/dev/null 2>&1; then
      echo "BLOCKED: pattern '$p' found in $f:"; grep -I -E -n -- "$p" "$f" | head -3
      rc=1
    fi
  done
  # 64-hex private-key-looking strings outside known test-vector files
  if [[ "$f" != Tests/* && "$f" != *.md ]]; then
    if grep -I -E -n -- '(private[_ -]?key|seed|mnemonic)[^\n]{0,40}[0-9a-fA-F]{64}' "$f" >/dev/null 2>&1; then
      echo "BLOCKED: 64-hex value near private-key/seed wording in $f"; rc=1
    fi
  fi
done
exit $rc
