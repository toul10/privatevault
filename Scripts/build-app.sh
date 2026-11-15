#!/bin/zsh
# Builds the PrivateVault app bundle with Swift Package Manager and signs it ad-hoc with the hardened runtime and the
# App Sandbox.
#
# Usage: Scripts/build-app.sh [--production] [--debug]
#   (default)     dist/PrivateVault Dev.app — bundle id com.kostastoulis.privatevault.dev
#                 A DEVELOPMENT build. Its own sandbox container, so it can never open, migrate or damage the vault
#                 of a PrivateVault installed on the same Mac. Use it for testing changes.
#   --production  dist/PrivateVault.app     — bundle id com.kostastoulis.privatevault (the real app identity)
#                 Opens the same vault as an installed PrivateVault. Use it only to produce a release (RELEASING.md).
#   --debug       Debug configuration + debug entitlements (combines with either identity). Never distribute.
#
# Safety: the script replaces only the bundle it is building inside dist/. It never touches /Applications, never quits
# an installed copy, and leaves dist/ unchanged if the build fails. Building the SwiftUI app needs Xcode 26 or newer
# (the Command Line Tools for Swift 6.4 ship without the SwiftUI macro plugin); the core and its tests build with the
# Command Line Tools alone (Scripts/run-tests.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

PROD_ID=com.kostastoulis.privatevault
CONFIG=release
ENT=Packaging/PrivateVault.entitlements
BUNDLE_ID=$PROD_ID.dev
APP_NAME="PrivateVault Dev"
for arg in "$@"; do
  case "$arg" in
    --production) BUNDLE_ID=$PROD_ID; APP_NAME=PrivateVault;;
    --debug)      CONFIG=debug; ENT=Packaging/PrivateVault-debug.entitlements;;
    *) echo "Unknown option: $arg   (usage: Scripts/build-app.sh [--production] [--debug])" >&2; exit 2;;
  esac
done
APP="dist/$APP_NAME.app"

if [[ "$(git config core.hooksPath 2>/dev/null)" != ".githooks" ]]; then
  echo "NOTE: secret-scan hooks are not active in this clone. Run: git config core.hooksPath .githooks"
fi

echo "▸ Building $APP_NAME ($CONFIG, $BUNDLE_ID)…"
log="$(mktemp "${TMPDIR:-/tmp}/pv-build.XXXXXX")"   # explicit template: works with BSD and GNU mktemp
if ! swift build -c "$CONFIG" --product PrivateVaultApp >"$log" 2>&1; then
  grep -E "error" "$log" | head -20 || true
  echo "✗ Build failed — nothing in dist/ was changed. Full log: $log" >&2
  exit 1
fi
grep -E "Build complete" "$log" | tail -1 || true
BIN="$(swift build -c "$CONFIG" --show-bin-path)/PrivateVaultApp"
[[ -f "$BIN" ]] || { echo "✗ Built binary not found at $BIN — nothing in dist/ was changed." >&2; exit 1; }

echo "▸ Assembling $APP…"
# Quit only the copy that is about to be replaced (matched by its full path) — never an installed PrivateVault.
pkill -f "$PWD/$APP/Contents/MacOS/PrivateVault" 2>/dev/null || true
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/PrivateVault"
cp Packaging/Info.plist "$APP/Contents/Info.plist"
if [[ "$BUNDLE_ID" != "$PROD_ID" ]]; then
  plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$APP/Contents/Info.plist"
  plutil -replace CFBundleName -string "$APP_NAME" "$APP/Contents/Info.plist"
  plutil -replace CFBundleDisplayName -string "$APP_NAME" "$APP/Contents/Info.plist"
fi
cp Packaging/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
printf 'APPL????' > "$APP/Contents/PkgInfo"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# Back-deployment shim only if the linker referenced it. Taken from the toolchain that built the binary.
if otool -L "$APP/Contents/MacOS/PrivateVault" | grep -q "@rpath/libswiftCompatibilitySpan.dylib"; then
  shim=""
  # (N) = zsh null glob: no match yields an empty list instead of aborting the script.
  for candidate in "$(dirname "$(xcrun --find swiftc)")"/../lib/swift-*/macosx/libswiftCompatibilitySpan.dylib(N) \
                   /Library/Developer/CommandLineTools/usr/lib/swift-6.2/macosx/libswiftCompatibilitySpan.dylib; do
    [[ -f "$candidate" ]] && { shim="$candidate"; break; }
  done
  [[ -n "$shim" ]] || { echo "✗ libswiftCompatibilitySpan.dylib is referenced but was not found in the toolchain" >&2; exit 1; }
  mkdir -p "$APP/Contents/Frameworks"
  cp "$shim" "$APP/Contents/Frameworks/"
  install_name_tool -add_rpath @executable_path/../Frameworks "$APP/Contents/MacOS/PrivateVault"
  codesign --force --sign - --options runtime "$APP/Contents/Frameworks/libswiftCompatibilitySpan.dylib"
fi

echo "▸ Signing (ad-hoc, hardened runtime, sandbox)…"
codesign --force --sign - --identifier "$BUNDLE_ID" --options runtime --timestamp=none \
  --entitlements "$ENT" "$APP"
codesign --verify --strict --verbose=1 "$APP"
Scripts/verify-bundle.sh "$APP"
echo "✓ Built $APP   (run: open \"$APP\")"
if [[ "$BUNDLE_ID" == "$PROD_ID" ]]; then
  echo "  Production identity: opens the same vault as an installed PrivateVault. Ad-hoc signed — do not distribute"
  echo "  (Developer ID signing and notarization: RELEASING.md)."
fi
