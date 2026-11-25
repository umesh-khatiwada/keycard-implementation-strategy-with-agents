#!/usr/bin/env bash
# Start a clean mock environment, run the acceptance suite, stop everything.
set -uo pipefail
cd "$(dirname "$0")/.."
export KEYCARD_ZONE_URL=http://localhost:9000   # services + tests use the mock zone...
export KEYCARD_LAB_NO_DOTENV=1                  # ...and ignore a real-zone .env entirely
./mz down >/dev/null 2>&1
rm -rf mockzone/.state/state.json .tokens
./mz up || exit 1
.venv/bin/python tests/acceptance.py
rc=$?
./mz down >/dev/null
exit $rc
