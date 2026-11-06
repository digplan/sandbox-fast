#!/usr/bin/env zsh
set -euo pipefail

cd "${0:A:h}"

# Stop any lingering daemon from manual CLI testing before running the 1,000-container test
./sbx daemon stop >/dev/null 2>&1 || true

# Ensure test_1000 binary is built with -O3 -flto
if [[ ! -x ./test_1000 || test_1000.c -nt ./test_1000 || sbx.c -nt ./test_1000 ]]; then
    make test_1000 >/dev/null
fi

./test_1000 "$@"
