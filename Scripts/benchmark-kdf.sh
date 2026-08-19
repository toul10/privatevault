#!/bin/zsh
# Measures Argon2id candidates in a RELEASE build on this Mac. Use the output to set KDFParameters.current
# (target: 0.5–1.0 s per unlock; never below the floor m ≥ 64 MiB, t ≥ 3).
cd "$(dirname "$0")/.."
PV_BENCH=1 exec Scripts/run-tests.sh -c release --filter KDFBenchmark "$@"
