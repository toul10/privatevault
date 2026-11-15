#!/bin/zsh
# Runs the PrivateVault test suite (Swift Testing).
# Usage: Scripts/run-tests.sh [-c release] [extra swift test args, e.g. --filter KDF]
#
# Builds the whole package with its test bundle (`swift build --build-tests`). Where the SwiftUI app cannot be
# compiled — the Command Line Tools for Swift 6.4 ship without the SwiftUI macro plugin — it builds only the test
# target and what it depends on (VaultCore, CArgon2, CSecureMemory); Swift 6.4 links the test bundle as part of that
# target, earlier SwiftPM versions (e.g. Xcode 26.x, used by CI) only compile it, hence the full build first.
# Any other build error stops the script. Works with the Command Line Tools and with Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."

toolchain=()
# `swift test` loads the Swift Testing macro plugin by itself; `swift build --target` does not, so point the compiler
# at the active toolchain's plugin directory (same layout in the Command Line Tools and in Xcode).
testing_plugins="$(dirname "$(xcrun --find swiftc)")/../lib/swift/host/plugins/testing"
[[ -d "$testing_plugins" ]] && toolchain+=(-Xswiftc -plugin-path -Xswiftc "$testing_plugins")
if [[ "$(xcode-select -p 2>/dev/null)" == /Library/Developer/CommandLineTools* ]]; then
  # Command Line Tools keep Swift Testing outside the default search paths.
  F=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
  L=/Library/Developer/CommandLineTools/Library/Developer/usr/lib
  if [[ ! -d "$F/Testing.framework" ]]; then
    echo "Swift Testing framework not found at $F — install/update Command Line Tools (xcode-select --install)." >&2
    exit 1
  fi
  toolchain+=(-Xswiftc -F"$F" -Xlinker -F"$F" -Xlinker -rpath -Xlinker "$F" -Xlinker -rpath -Xlinker "$L")
fi

# -c/--configuration must reach both the build and the run step; everything else goes to `swift test`.
config=()
test_args=()
while (( $# )); do
  case "$1" in
    -c|--configuration) config=("$1" "$2"); shift 2;;
    *) test_args+=("$1"); shift;;
  esac
done

# `swift test` compiles VaultCore for @testable import by itself (also in release); `swift build` must be told so.
# Both builds use identical flags, so the fallback reuses everything the first attempt compiled.
log="$(mktemp "${TMPDIR:-/tmp}/pv-tests.XXXXXX")"   # explicit template: works with BSD and GNU mktemp
echo "▸ Building the package and its tests…"
if swift build --build-tests -Xswiftc -enable-testing "${config[@]}" "${toolchain[@]}" >"$log" 2>&1; then
  grep -E "Build complete" "$log" | tail -1 || true
elif grep -q "plugin for module 'SwiftUIMacros' not found" "$log"; then
  echo "NOTE: this toolchain cannot compile the SwiftUI app (no SwiftUI macro plugin) — building only the core and its tests."
  swift build --target VaultCoreTests -Xswiftc -enable-testing "${config[@]}" "${toolchain[@]}"
else
  grep -E "error:" "$log" | head -40 >&2 || true
  echo "✗ Build failed — full log: $log" >&2
  exit 1
fi
exec swift test --skip-build --disable-xctest "${config[@]}" "${toolchain[@]}" "${test_args[@]}"
