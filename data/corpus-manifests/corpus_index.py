#!/usr/bin/env python3
"""Verify a corpus input against the published release checksums.

Counting inputs is not enough and neither is naming them. A stream that is
present, carries the right run id in every record, and has simply been
truncated will pass both of those checks and still move a reported number --
one such truncation shifted a B1/B2 false-positive count and exited 0. The only
check that closes the class is the content hash, so the scorers verify each
input they read against ``ARCHIVE_SHA256SUMS.txt``, the index published beside
the corpus volumes and mirrored here.

The index keys are relative to the corpus payload root; the volumes unpack to
several different places under ``data/``, so ``payload_key`` maps a repository
path back to its key. A file that is not in the index, or that hashes
differently, is not the input the frozen outputs were computed from -- whatever
else is true of it.

This is a reproduction check, not a security boundary: anyone who can rewrite
the inputs can rewrite this index too. What it buys is that an accidentally
truncated, half-copied or substituted input cannot quietly republish different
numbers under a frozen filename.
"""
import hashlib
import os
from pathlib import Path

INDEX_NAME = "ARCHIVE_SHA256SUMS.txt"

# repository prefix -> corpus payload prefix
LAYOUT = (
    ("data/corpus-manifests/", ""),                        # tier_a/ tier_b/ tier_c/ manifests/
    ("data/superseded/staging/", "staging/"),
    ("data/provenance/inputs/", "provenance-inputs/"),
    ("data/aux/", "aux/"),
)

_CACHE: dict = {}


def index_path(root) -> Path:
    return Path(root) / "data/corpus-manifests" / INDEX_NAME


def load(root):
    """The published index as {payload-relative path: sha256}, or None if absent."""
    p = index_path(root)
    key = str(p)
    if key not in _CACHE:
        if not p.is_file():
            return None
        table = {}
        with p.open() as fh:
            for line in fh:
                digest, _, rel = line.rstrip("\n").partition("  ")
                if rel:
                    table[rel] = digest
        _CACHE[key] = table
    return _CACHE[key]


def payload_key(rel_repo_path):
    """Map a repository-relative path to its key in the published index."""
    p = str(rel_repo_path).replace(os.sep, "/")
    for prefix, replacement in LAYOUT:
        if p.startswith(prefix):
            return replacement + p[len(prefix):]
    return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(path, root, digest=None):
    """None if `path` matches its published checksum, else why it does not.

    Pass `digest` when the caller has already hashed the bytes it read, so a
    stream is not read twice.
    """
    table = load(root)
    if table is None:
        return f"the release checksum index {INDEX_NAME} is missing"
    try:
        rel = Path(path).resolve().relative_to(Path(root).resolve())
    except ValueError:
        return f"{path} is outside the repository"
    key = payload_key(rel)
    if key is None:
        return f"{rel} is not in a directory the corpus volumes unpack into"
    want = table.get(key)
    if want is None:
        return f"{key} is not listed in {INDEX_NAME}"
    got = digest or sha256_file(path)
    if got != want:
        return f"{key} hashes to {got[:12]}..., published {want[:12]}..."
    return None


def check_tree(root_dir, root, limit=None):
    """Every file under `root_dir` must be present in the index and match it.

    An unlisted file is a failure too: these trees are published wholesale, so
    a file that is not in the index was not part of what shipped.
    """
    bad = []
    for path in sorted(Path(root_dir).rglob("*")):
        if not path.is_file():
            continue
        why = check(path, root)
        if why:
            bad.append(why)
            if limit and len(bad) >= limit:
                break
    return bad
