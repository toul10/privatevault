#!/bin/zsh
# Runs the PrivateVault test suite (Swift Testing).
# Usage: Scripts/run-tests.sh [-c release] [extra swift test args, e.g. --filter KDF]
#
# Builds ONLY the test target and what it depends on (VaultCore, CArgon2, CSecureMemory), never the SwiftUI app.
# So the suite runs even where the app cannot be compiled — e.g. Command Line Tools for Swift 6.4, which ship
# without the SwiftUI macro plugin. Works with the Command Line Tools and with Xcode (used by CI).
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
swift build --target VaultCoreTests -Xswiftc -enable-testing "${config[@]}" "${toolchain[@]}"
exec swift test --skip-build --disable-xctest "${config[@]}" "${toolchain[@]}" "${test_args[@]}"
