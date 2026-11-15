#!/bin/zsh
# Greps the source tree for anything that could talk to a network or phone home. Expected result: nothing.
# Usage: Scripts/audit-network.sh [--strict]    --strict (CI): exit 1 if any indicator is found.
cd "$(dirname "$0")/.."
strict=0; [[ "${1:-}" == "--strict" ]] && strict=1
pattern='URLSession|NSURLConnection|CFNetwork|Network\.framework|NWConnection|NWListener|WebSocket|URLRequest|http://|https://|analytics|telemetry|Sentry|Firebase|Crashlytics|MetricKit|socket\(|getaddrinfo|connect\('
echo "▸ Scanning Sources/ and Package.swift for network/telemetry indicators…"
hits=$(grep -rnE "$pattern" Sources Package.swift 2>/dev/null | grep -vE "^\S+:\s*//|https://binance.com|example\.com|https://παράδειγμα|\.privatevault|// no network|rfc-editor|github.com/P-H-C|download.libsodium|apache.org|creativecommons|creativecommons.org|w3.org|apple.com/DTDs|No network access, no telemetry" || true)
if [[ -n "$hits" ]]; then
  echo "Potential indicators (review each — placeholders and comments are expected):"; echo "$hits"
  (( strict )) && { echo "✗ --strict: network/telemetry indicators found"; exit 1; }
else
  echo "✓ no network / telemetry indicators in Sources/"
fi
echo "▸ Checking entitlements of dist/PrivateVault.app (if built)…"
if [[ -d dist/PrivateVault.app ]]; then
  if codesign -d --entitlements - dist/PrivateVault.app 2>/dev/null | grep -q network; then echo "✗ network entitlement present"; exit 1; else echo "✓ no network entitlement (sandbox blocks sockets)"; fi
fi
echo "▸ Linked frameworks of the binary:"
if [[ -f dist/PrivateVault.app/Contents/MacOS/PrivateVault ]]; then otool -L dist/PrivateVault.app/Contents/MacOS/PrivateVault | grep -iE "CFNetwork|Network\.framework" && echo "(CFNetwork is pulled in transitively by Foundation/AppKit; the sandbox denies sockets anyway)" || echo "✓ no direct CFNetwork/Network.framework link"; fi
exit 0
