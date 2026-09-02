"""Per-path serialization of file mutations.

Port of `pi-coding-agent/src/core/tools/file-mutation-queue.ts`. The upstream
module chains promises keyed by canonical path so that concurrent writes to
the same file execute sequentially. It explicitly DOES NOT implement atomic
writes — the caller (pi_tools.write / pi_tools.edit) uses direct
fs.writeFile, and the queue only prevents interleaved writes.

Our harness mirrors that contract using threading.Lock per canonical path.
For a single-threaded harness session this is a no-op, but the primitive is
available for future concurrency (e.g. background heartbeat writes racing
with the main session).
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Iterator


class FileMutationQueue:
    """Serialize mutations per canonical file path.

    Port of the promise-chain in file-mutation-queue.ts. Re-entrant within
    the same thread (in case a tool wrapper calls itself).
    """

    def __init__(self) -> None:
        self._locks: dict[str, threading.RLock] = {}
        self._meta_lock = threading.Lock()

    def _key(self, path: str) -> str:
        """Resolve to a canonical absolute path for locking.

        Using realpath so that symlink aliases of the same file share a lock.
        """
        try:
            return os.path.realpath(path)
        except OSError:
            return os.path.abspath(path)

    def _get_lock(self, canonical: str) -> threading.RLock:
        with self._meta_lock:
            lock = self._locks.get(canonical)
            if lock is None:
                lock = threading.RLock()
                self._locks[canonical] = lock
            return lock

    @contextmanager
    def acquire(self, path: str) -> Iterator[None]:
        """Context manager that holds the per-path lock for the duration of `with`."""
        canonical = self._key(path)
        lock = self._get_lock(canonical)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()


# Default shared queue — the session runner creates one per agent instance.
_DEFAULT_QUEUE = FileMutationQueue()


def default_queue() -> FileMutationQueue:
    """Return the process-wide default queue.

    Only use this in simple single-session harness code. Long-lived runners
    should create their own queue so tests can isolate state.
    """
    return _DEFAULT_QUEUE
