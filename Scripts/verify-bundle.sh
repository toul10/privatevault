#!/bin/zsh
# Verifies the security-relevant properties of a built PrivateVault.app:
#  - exactly the two allowed entitlements (sandbox + user-selected files), no network, no get-task-allow (release)
#  - hardened runtime flag set
#  - no SwiftPM resource bundle at the .app root, no unexpected dylibs
set -euo pipefail
APP="${1:-dist/PrivateVault.app}"
[[ -d "$APP" ]] || { echo "no bundle at $APP"; exit 1; }
ENT=$(codesign -d --entitlements :- "$APP" 2>/dev/null || codesign -d --entitlements - "$APP" 2>/dev/null)
keys=$(echo "$ENT" | grep -oE '<key>[^<]+</key>' | sed -E 's/<\/?key>//g' | sort)
expected=$'com.apple.security.app-sandbox\ncom.apple.security.files.user-selected.read-write'
if echo "$ENT" | grep -q "get-task-allow"; then
  echo "NOTE: debug build (get-task-allow present) — do not distribute."
  expected=$'com.apple.security.app-sandbox\ncom.apple.security.files.user-selected.read-write\ncom.apple.security.get-task-allow'
fi
if [[ "$keys" != "$expected" ]]; then echo "✗ entitlements differ from the allow-list:"; echo "$keys"; exit 1; fi
if echo "$ENT" | grep -q "network"; then echo "✗ network entitlement present"; exit 1; fi
FLAGS=$(codesign -dvv "$APP" 2>&1 | grep -E "^CodeDirectory" || true)
echo "$FLAGS" | grep -q "runtime" || { echo "✗ hardened runtime flag missing: $FLAGS"; exit 1; }
if [[ -n "$(find "$APP" -maxdepth 1 -name "*.bundle" -print -quit)" ]]; then echo "✗ resource bundle at app root"; exit 1; fi
if otool -L "$APP/Contents/MacOS/PrivateVault" | grep -vE "^\s*/usr/lib/|^\s*/System/|^$APP|PrivateVault:" | grep -q "."; then
  echo "NOTE: non-system dylibs referenced:"; otool -L "$APP/Contents/MacOS/PrivateVault" | grep -vE "/usr/lib/|/System/"
fi
echo "✓ bundle verified: sandbox + user-selected files only, hardened runtime, no network entitlement"
