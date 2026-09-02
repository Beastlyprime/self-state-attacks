#!/usr/bin/env bash
# Reproduce the P3 prevention mechanism x operation replay matrix.
#
# Deterministic OS-mechanism probe (no agent runtime, no model request). Requires
# a privileged container so a trusted supervisor can install the controls
# (chattr +i, AppArmor, Landlock, DAC chown-root); the attack operations then run
# under an unprivileged agent uid. The kernel errno semantics are
# architecture-independent, so the host arch is immaterial.
#
# Usage:  REPO_ROOT=/path/to/repo WORK=/path/to/ext4/scratch bash run_p3_op_matrix.sh
set -euo pipefail

# repo root: two dirs up from this script's grandparent (…/<artifact>/bin/ -> repo)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$HERE/../../../.." && pwd)}"
WORK="${WORK:-$HERE}"                       # must be on an ext4 mount for chattr +i
IMAGE="${IMAGE:-ubuntu:22.04}"

docker run --rm --privileged \
  -v "$WORK":/work \
  -v "$REPO_ROOT":/repo:ro \
  "$IMAGE" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq python3 gcc apparmor apparmor-utils util-linux e2fsprogs >/dev/null 2>&1
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
    python3 /repo/data/prevention/bin/p3_op_matrix_incontainer.py
  '
