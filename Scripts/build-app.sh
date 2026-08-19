#!/bin/zsh
# Builds PrivateVault.app with Swift Package Manager (no Xcode required) and signs it ad-hoc with the hardened
# runtime and App Sandbox. Usage: Scripts/build-app.sh [--debug]
#   Output: dist/PrivateVault.app
set -euo pipefail
cd "$(dirname "$0")/.."
CONFIG=release
ENT=Packaging/PrivateVault.entitlements
if [[ "${1:-}" == "--debug" ]]; then CONFIG=debug; ENT=Packaging/PrivateVault-debug.entitlements; fi
APP=dist/PrivateVault.app
BIN=.build/$CONFIG/PrivateVaultApp

if [[ "$(git config core.hooksPath 2>/dev/null)" != ".githooks" ]]; then
  echo "NOTE: pre-commit secret scan is not active in this clone. Run: git config core.hooksPath .githooks"
fi
echo "▸ Building ($CONFIG)…"
swift build -c "$CONFIG" --product PrivateVaultApp 2>&1 | grep -E "error|warning: unre|Compiling|Build complete|Linking" | tail -5

echo "▸ Assembling bundle…"
# quit a running copy first (overwriting a running signed binary kills it)
pkill -x PrivateVault 2>/dev/null || true
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/PrivateVault"
cp Packaging/Info.plist "$APP/Contents/Info.plist"
cp Packaging/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
printf 'APPL????' > "$APP/Contents/PkgInfo"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# Back-deployment shim only if the linker referenced it (not the case on this toolchain, but be safe).
if otool -L "$APP/Contents/MacOS/PrivateVault" | grep -q "@rpath/libswiftCompatibilitySpan.dylib"; then
  mkdir -p "$APP/Contents/Frameworks"
  cp /Library/Developer/CommandLineTools/usr/lib/swift-6.2/macosx/libswiftCompatibilitySpan.dylib "$APP/Contents/Frameworks/"
  install_name_tool -add_rpath @executable_path/../Frameworks "$APP/Contents/MacOS/PrivateVault"
  codesign --force --sign - --options runtime "$APP/Contents/Frameworks/libswiftCompatibilitySpan.dylib"
fi

echo "▸ Signing (ad-hoc, hardened runtime, sandbox)…"
codesign --force --sign - --identifier com.kostastoulis.privatevault --options runtime --timestamp=none \
  --entitlements "$ENT" "$APP"
codesign --verify --strict --verbose=1 "$APP"
Scripts/verify-bundle.sh "$APP"
echo "✓ Built $APP   (run: open $APP)"
