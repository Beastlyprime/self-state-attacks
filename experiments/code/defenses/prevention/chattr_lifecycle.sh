#!/usr/bin/env bash
# chattr_lifecycle.sh — Immutability lifecycle for identity files
#
# Manages the chattr +i (immutable) attribute on identity files.
# Provides lock/unlock/status operations and measures the temporal
# vulnerability window during unlock periods.
#
# Usage:
#   ./chattr_lifecycle.sh <agent_dir> lock|unlock|status|timed_unlock <seconds>
#
# Examples:
#   ./chattr_lifecycle.sh /srv/assa-agent lock
#   ./chattr_lifecycle.sh /srv/assa-agent timed_unlock 5
#
# NOTE: chattr requires root/CAP_LINUX_IMMUTABLE. In experiments,
# this runs as root or via sudo from watchdog-user.

set -euo pipefail

AGENT_DIR="${1:?Usage: $0 <agent_dir> lock|unlock|status|timed_unlock [seconds]}"
ACTION="${2:?Usage: $0 <agent_dir> lock|unlock|status|timed_unlock [seconds]}"

IDENTITY_FILES=(
    "${AGENT_DIR}/soul.md"
    "${AGENT_DIR}/agents.md"
)

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
LOG_PREFIX="[CHATTR ${TIMESTAMP}]"

log() {
    echo "${LOG_PREFIX} $*"
}

check_files_exist() {
    for f in "${IDENTITY_FILES[@]}"; do
        if [ ! -f "$f" ]; then
            log "ERROR: File not found: $f"
            exit 1
        fi
    done
}

get_immutable_status() {
    local file="$1"
    # lsattr output: ----i--------e-- filename
    if lsattr "$file" 2>/dev/null | grep -q "i"; then
        echo "immutable"
    else
        echo "mutable"
    fi
}

do_lock() {
    check_files_exist
    for f in "${IDENTITY_FILES[@]}"; do
        chattr +i "$f" 2>/dev/null || {
            log "WARNING: chattr +i failed on $f (need root/CAP_LINUX_IMMUTABLE)"
            log "SIMULATING: marking $f as immutable (simulation mode)"
            # In simulation mode, record the lock event
            echo "${TIMESTAMP} LOCK $f" >> "${AGENT_DIR}/.chattr_log"
            continue
        }
        log "LOCKED: $f (immutable)"
    done
    echo "${TIMESTAMP} LOCK_ALL" >> "${AGENT_DIR}/.chattr_log" 2>/dev/null || true
}

do_unlock() {
    check_files_exist
    local unlock_time
    unlock_time=$(date +%s%N)
    for f in "${IDENTITY_FILES[@]}"; do
        chattr -i "$f" 2>/dev/null || {
            log "WARNING: chattr -i failed on $f (simulation mode)"
            echo "${TIMESTAMP} UNLOCK $f" >> "${AGENT_DIR}/.chattr_log"
            continue
        }
        log "UNLOCKED: $f (mutable — VULNERABILITY WINDOW OPEN)"
    done
    echo "${TIMESTAMP} UNLOCK_ALL start_ns=${unlock_time}" >> "${AGENT_DIR}/.chattr_log" 2>/dev/null || true
}

do_status() {
    check_files_exist
    log "Identity file status:"
    for f in "${IDENTITY_FILES[@]}"; do
        status=$(get_immutable_status "$f")
        log "  $(basename $f): ${status}"
    done
}

do_timed_unlock() {
    local seconds="${3:?Usage: $0 <agent_dir> timed_unlock <seconds>}"
    check_files_exist

    local start_ns
    start_ns=$(date +%s%N)

    log "TIMED UNLOCK: ${seconds}s vulnerability window"
    do_unlock

    sleep "$seconds"

    do_lock
    local end_ns
    end_ns=$(date +%s%N)

    local window_ms=$(( (end_ns - start_ns) / 1000000 ))
    log "TIMED UNLOCK COMPLETE: window=${window_ms}ms (requested=${seconds}s)"
    echo "${TIMESTAMP} TIMED_UNLOCK duration_ms=${window_ms} requested_s=${seconds}" >> "${AGENT_DIR}/.chattr_log" 2>/dev/null || true

    # Output for measurement scripts
    echo "vulnerability_window_ms=${window_ms}"
}

case "$ACTION" in
    lock)
        do_lock
        ;;
    unlock)
        do_unlock
        ;;
    status)
        do_status
        ;;
    timed_unlock)
        do_timed_unlock "$@"
        ;;
    *)
        echo "Unknown action: $ACTION"
        echo "Usage: $0 <agent_dir> lock|unlock|status|timed_unlock [seconds]"
        exit 1
        ;;
esac
