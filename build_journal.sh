#!/bin/bash
set -euo pipefail
CC=${CC:-gcc}

$CC -O2 -Wall -Wextra -Wno-deprecated-declarations \
    -I/usr/local/include -L/usr/local/lib \
    src/apake_bench_journal.c -o apake_bench_journal \
    -loqs -lcrypto -largon2 -lm

echo "[OK] built ./apake_bench_journal"
