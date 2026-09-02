#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUTPUT=${1:-"${SCRIPT_DIR}/assa-landlock"}

cc -O2 -Wall -Wextra -Werror \
  "${SCRIPT_DIR}/landlock_launcher.c" \
  -o "${OUTPUT}"
"${OUTPUT}" --probe
