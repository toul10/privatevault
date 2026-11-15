#!/bin/zsh
# Secret scan: keeps vault files, backups, signing material, secrets and private e-mail addresses out of the
# repository AND out of its history.
#   Scripts/secret-scan.sh                     STAGED content (the pre-commit hook; default)
#   Scripts/secret-scan.sh --all               every tracked file in the working tree (final audit, CI)
#   Scripts/secret-scan.sh --commits <revs>    every file version in the given commits (git rev-list arguments, e.g.
#                                              HEAD or origin/main..HEAD) and each commit's author/committer e-mail,
#                                              which must be a GitHub noreply address (the pre-push hook, CI)
# Exit 1 on any hit. Frozen test fixtures with FAKE credentials are allow-listed below.
set -uo pipefail
cd "$(dirname "$0")/.."
mode="${1:-staged}"
rc=0

# Content patterns (case-insensitive where lookalike forms are accepted by the app)
patterns=(
  '-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
  'sk_live_[0-9a-zA-Z]{24,}'               # Stripe live secret
  'xox[baprs]-[0-9A-Za-z-]{10,}'           # Slack token
  'ghp_[0-9A-Za-z]{36}'                    # GitHub PAT
  'github_pat_[0-9A-Za-z_]{20,}'           # GitHub fine-grained PAT
  'sk-(proj-)?[0-9A-Za-z_-]{32,}'          # OpenAI-style API key
  '(AKIA|ASIA)[0-9A-Z]{16}'                # AWS (incl. temporary) access key ids
  'xprv[0-9A-Za-z]{100,}'                  # BIP32 extended private key
)
# PrivateVault Recovery Kit: prefix optional, separators optional, any case, I/L/O lookalikes (as RecoveryKit.decode accepts)
kit_pattern='(PV1[- ])?([0-9A-HJKMNP-TV-ZILO]{5}[- ]){10}[0-9A-HJKMNP-TV-ZILO]{5}'

# Forbidden file types: vault data, backups, signing material, archives/bundles, personal documents, .env files.
check_type() {   # $1 = repository path
  [[ "$1" == Tests/VaultCoreTests/Fixtures/golden-v1.* ]] && return 0   # frozen format fixture with FAKE credentials
  case "$1" in
    *.sqlite|*.sqlite-wal|*.sqlite-shm|*.sqlite-journal|*.db|*.privatevault|*.p12|*.pem|*.key|*.mobileprovision|*.provisionprofile|*.p8|*.keychain|*.keychain-db|*.certSigningRequest|*.cer|*.bundle|*.zip|*.dmg|*.rtf|*.env|*.env.*)
      echo "BLOCKED: forbidden file type: $1"; rc=1;;
  esac
}

# Content checks on the global $blob, the content of repository path $1, reported as $2.
check_blob() {
  local f="$1" where="$2" p
  [[ "$f" == Tests/VaultCoreTests/Fixtures/* ]] && return 0
  [[ -z "$blob" ]] && return 0
  # skip binaries (contain NUL bytes)
  if printf '%s' "$blob" | perl -0777 -ne 'exit(index($_, "\0") >= 0 ? 0 : 1)'; then return 0; fi
  for p in "${patterns[@]}"; do
    if printf '%s\n' "$blob" | grep -E -n -- "$p" >/dev/null 2>&1; then
      echo "BLOCKED: pattern '$p' found in $where:"; printf '%s\n' "$blob" | grep -E -n -- "$p" | head -3
      rc=1
    fi
  done
  if printf '%s\n' "$blob" | grep -i -E -n -- "$kit_pattern" >/dev/null 2>&1; then
    echo "BLOCKED: Recovery-Kit-looking string in $where:"; printf '%s\n' "$blob" | grep -i -E -n -- "$kit_pattern" | head -3 | cut -c1-120
    rc=1
  fi
  # 64-hex private-key-looking strings outside docs (tests use obviously fake, non-hex values)
  if [[ "$f" != *.md ]]; then
    if printf '%s\n' "$blob" | grep -i -E -n -- '(private[_ -]?key|seed|mnemonic)[^\n]{0,40}[0-9a-f]{64}' >/dev/null 2>&1; then
      echo "BLOCKED: 64-hex value near private-key/seed wording in $where"; rc=1
    fi
  fi
}

# A commit's e-mail addresses become public on push; only GitHub noreply addresses may leave this Mac.
check_identity() {   # $1 = commit
  [[ "${PV_ALLOW_PUBLIC_EMAIL:-0}" == 1 ]] && return 0
  local e
  for e in "$(git log -1 --format=%ae "$1")" "$(git log -1 --format=%ce "$1")"; do
    if [[ "$e" != *@users.noreply.github.com && "$e" != noreply@github.com ]]; then
      echo "BLOCKED: commit ${1[1,12]} carries the e-mail address '$e', which would become public."
      echo "         Fix: git config user.email <id>+<login>@users.noreply.github.com, then rewrite the commit."
      echo "         To publish it deliberately: PV_ALLOW_PUBLIC_EMAIL=1"
      rc=1
    fi
  done
}

case "$mode" in
  --commits)
    shift
    (( $# )) || { echo "usage: Scripts/secret-scan.sh --commits <git rev-list arguments>" >&2; exit 2; }
    commits=$(git rev-list "$@") || { echo "BLOCKED: cannot list commits for: $*" >&2; exit 1; }
    for c in ${(f)commits}; do
      check_identity "$c"
      files=$(git diff-tree --root --no-commit-id --name-only -r --diff-filter=ACMRT "$c")
      for f in ${(f)files}; do
        check_type "$f"
        blob=$(git show "$c:$f" 2>/dev/null) || continue
        check_blob "$f" "$f @ ${c[1,12]}"
      done
    done
    ;;
  --all|staged)
    if [[ "$mode" == --all ]]; then files=$(git ls-files)
    else files=$(git diff --cached --name-only --diff-filter=ACMRT); fi
    [[ -z "$files" ]] && exit 0
    for f in ${(f)files}; do check_type "$f"; done
    for f in ${(f)files}; do
      if [[ "$mode" == --all ]]; then blob=$(cat -- "$f" 2>/dev/null) || continue
      else blob=$(git show ":$f" 2>/dev/null) || continue; fi   # the staged blob, not the working tree
      check_blob "$f" "$f"
    done
    ;;
  *) echo "usage: Scripts/secret-scan.sh [--all | --commits <git rev-list arguments>]" >&2; exit 2;;
esac
exit $rc
