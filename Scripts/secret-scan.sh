#!/bin/zsh
# Secret scan: keeps vault files, backups, signing material, secrets and private e-mail addresses out of the
# repository AND out of its history. It is a safety net, not a guarantee: never copy personal files into the repo.
#   Scripts/secret-scan.sh                     STAGED content (the pre-commit hook; default)
#   Scripts/secret-scan.sh --all               every tracked file in the working tree (final audit, CI)
#   Scripts/secret-scan.sh --commits <revs>    every file version in the given commits (git rev-list arguments, e.g.
#                                              HEAD or origin/main..HEAD), every commit message, and each commit's
#                                              author/committer e-mail, which must be a GitHub noreply address
#                                              (the pre-push hook, CI)
#   Scripts/secret-scan.sh --tag <object>      an annotated tag (and any tag it points to): tagger e-mail and message
# Exit 1 on any hit. Frozen test fixtures with FAKE credentials are allow-listed below.
set -uo pipefail
cd "$(dirname "$0")/.."
mode="${1:-staged}"
rc=0
usage() { echo "usage: Scripts/secret-scan.sh [--all | --commits <git rev-list arguments> | --tag <object>]" >&2; }

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
  'suiprivkey1[0-9a-z]{40,}'               # Sui private key (bech32)
  '"wrappedVMK"[[:space:]]*:[[:space:]]*"[^"]{40,}"'   # a real PrivateVault backup, whatever the file is called
)
# PrivateVault Recovery Kit, in every form RecoveryKit.decode accepts (any case, I/L/O lookalikes):
kit_grouped='(PV1[- ])?([0-9A-HJKMNP-TV-ZILO]{5}[- ]){10}[0-9A-HJKMNP-TV-ZILO]{5}'          # 11 groups, per line
kit_prefixed='PV1[-\s]*(?:[0-9A-HJKMNP-TV-ZILO][-\s]*){54}[0-9A-HJKMNP-TV-ZILO]'           # any/no separators, line breaks

# Forbidden file types (case-insensitive): vault data, password-manager exports, signing material, archives and
# bundles, personal documents, .env files; images and PDFs only under Packaging/ (a screenshot can show a secret).
check_type() {   # $1 = repository path
  local f="$1" lf="${1:l}"
  [[ "$f" == Tests/VaultCoreTests/Fixtures/golden-v1.* ]] && return 0   # frozen format fixture with FAKE credentials
  case "$lf" in
    *.sqlite|*.sqlite3|*.sqlite-wal|*.sqlite-shm|*.sqlite-journal|*.db|*.privatevault|*.kdbx|*.kdb|*.1pux|*.opvault|*.csv)
      echo "BLOCKED: forbidden file type (vault data / password export): $f"; rc=1;;
    *.p12|*.pfx|*.pem|*.key|*.p8|*.cer|*.crt|*.certsigningrequest|*.mobileprovision|*.provisionprofile|*.keychain|*.keychain-db)
      echo "BLOCKED: forbidden file type (keys / signing material): $f"; rc=1;;
    *.bundle|*.zip|*.dmg|*.tar|*.tgz|*.gz|*.bz2|*.xz|*.7z|*.rar|*.rtf|*.env|*.env.*)
      echo "BLOCKED: forbidden file type (archive / document / .env): $f"; rc=1;;
    *.png|*.jpg|*.jpeg|*.heic|*.gif|*.tif|*.tiff|*.bmp|*.webp|*.pdf|*.mov|*.mp4)
      [[ "$f" == Packaging/* ]] || { echo "BLOCKED: image or PDF outside Packaging/ (could show a secret): $f"; rc=1; };;
  esac
}

# Content checks on the global $blob, the content of repository path $1, reported as $2.
check_blob() {
  local f="$1" where="$2" p
  [[ "$f" == Tests/VaultCoreTests/Fixtures/* ]] && return 0
  [[ -z "$blob" ]] && return 0
  if [[ "$blob" == "SQLite format 3"* ]]; then echo "BLOCKED: SQLite database (a vault?) in $where"; rc=1; return 0; fi
  # skip other binaries (contain NUL bytes)
  if printf '%s' "$blob" | perl -0777 -ne 'exit(index($_, "\0") >= 0 ? 0 : 1)'; then return 0; fi
  for p in "${patterns[@]}"; do
    if printf '%s\n' "$blob" | grep -E -n -- "$p" >/dev/null 2>&1; then
      echo "BLOCKED: pattern '$p' found in $where:"; printf '%s\n' "$blob" | grep -E -n -- "$p" | head -3 | cut -c1-120
      rc=1
    fi
  done
  if printf '%s\n' "$blob" | grep -i -E -n -- "$kit_grouped" >/dev/null 2>&1; then
    echo "BLOCKED: Recovery-Kit-looking string in $where:"; printf '%s\n' "$blob" | grep -i -E -n -- "$kit_grouped" | head -3 | cut -c1-120
    rc=1
  elif printf '%s' "$blob" | KIT="$kit_prefixed" perl -0777 -ne 'exit(/$ENV{KIT}/i ? 0 : 1)'; then
    echo "BLOCKED: Recovery Kit (PV1 + 55 symbols, any separators) in $where"; rc=1
  fi
  # 64-hex private-key-looking strings. Exempt: docs, and Tests/VaultCoreTests/Crypto/, which holds only PUBLISHED
  # known-answer vectors (RFC 9106, RFC 5869, RFC 9180, NIST); every other rule still applies there.
  if [[ "$f" != *.md && "$f" != Tests/VaultCoreTests/Crypto/* ]]; then
    if printf '%s\n' "$blob" | grep -i -E -n -- '(private[_ -]?key|seed|mnemonic).{0,40}[0-9a-f]{64}' >/dev/null 2>&1; then
      echo "BLOCKED: 64-hex value near private-key/seed wording in $where"; rc=1
    fi
  fi
}

# E-mail addresses in commits and tags become public on push; only GitHub noreply addresses may leave this Mac.
check_email() {   # $1 = address, $2 = where it was found
  [[ "${PV_ALLOW_PUBLIC_EMAIL:-0}" == 1 ]] && return 0
  if [[ "$1" != *@users.noreply.github.com && "$1" != noreply@github.com ]]; then
    echo "BLOCKED: $2 carries the e-mail address '$1', which would become public."
    echo "         Fix: git config user.email <id>+<login>@users.noreply.github.com, then rewrite it."
    echo "         To publish it deliberately: PV_ALLOW_PUBLIC_EMAIL=1"
    rc=1
  fi
}

case "$mode" in
  --commits)
    shift
    (( $# )) || { usage; exit 2; }
    commits=$(git rev-list "$@") || { echo "BLOCKED: cannot list commits for: $*" >&2; exit 1; }
    for c in ${(f)commits}; do
      check_email "$(git log -1 --format=%ae "$c")" "commit ${c[1,12]} (author)"
      check_email "$(git log -1 --format=%ce "$c")" "commit ${c[1,12]} (committer)"
      blob=$(git log -1 --format=%B "$c"); check_blob COMMIT_MESSAGE "the message of commit ${c[1,12]}"
      # -z: exact file names (no C-quoting of Greek/non-ASCII names, quotes, tabs, newlines); -m: merge commits too
      for f in ${(0)"$(git diff-tree -z -m -r --root --no-commit-id --name-only --diff-filter=ACMRT "$c")"}; do
        check_type "$f"
        blob=$(git show "$c:$f" 2>/dev/null) || { echo "BLOCKED: cannot read $f @ ${c[1,12]}"; rc=1; continue; }
        check_blob "$f" "$f @ ${c[1,12]}"
      done
    done
    ;;
  --tag)
    obj="${2:-}"; [[ -n "$obj" ]] || { usage; exit 2; }
    while [[ "$(git cat-file -t "$obj" 2>/dev/null)" == tag ]]; do
      raw=$(git cat-file tag "$obj")
      tagger=$(printf '%s\n' "$raw" | sed -n 's/^tagger .*<\([^>]*\)>.*/\1/p' | head -1)
      [[ -n "$tagger" ]] && check_email "$tagger" "tag ${obj[1,12]} (tagger)"
      blob=$(printf '%s\n' "$raw" | sed '1,/^$/d'); check_blob TAG_MESSAGE "the message of tag ${obj[1,12]}"
      obj=$(printf '%s\n' "$raw" | awk '/^object /{print $2; exit}')
    done
    ;;
  --all|staged)
    if [[ "$mode" == --all ]]; then names="$(git ls-files -z)"
    else names="$(git diff --cached -z --name-only --diff-filter=ACMRT)"; fi
    files=(${(0)names})                                   # exact names, NUL-separated (see --commits)
    (( ${#files} )) || exit 0
    for f in "${files[@]}"; do check_type "$f"; done
    for f in "${files[@]}"; do
      if [[ "$mode" == --all ]]; then blob=$(cat -- "$f" 2>/dev/null) || continue   # deleted locally: not a leak
      else blob=$(git show ":$f" 2>/dev/null) || { echo "BLOCKED: cannot read staged $f"; rc=1; continue; }; fi
      check_blob "$f" "$f"
    done
    ;;
  *) usage; exit 2;;
esac
exit $rc
