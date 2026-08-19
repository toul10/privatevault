#!/bin/zsh
# Runs the PrivateVault test suite with Swift Testing under Command Line Tools (no Xcode needed).
# Usage: Scripts/run-tests.sh [extra swift test args, e.g. --filter KDF]
set -euo pipefail
cd "$(dirname "$0")/.."
F=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
L=/Library/Developer/CommandLineTools/Library/Developer/usr/lib
if [[ ! -d "$F/Testing.framework" ]]; then
  echo "Swift Testing framework not found at $F — install/update Command Line Tools (xcode-select --install)." >&2
  exit 1
fi
exec swift test --disable-xctest \
  -Xswiftc -F"$F" -Xlinker -F"$F" \
  -Xlinker -rpath -Xlinker "$F" -Xlinker -rpath -Xlinker "$L" \
  "$@"
