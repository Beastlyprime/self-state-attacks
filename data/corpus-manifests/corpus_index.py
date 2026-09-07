#!/usr/bin/env python3
"""Verify a corpus input against the published release checksums.

Counting inputs is not enough and neither is naming them: a stream that is
present, carries the right run id in every record, and has been truncated
passes both of those checks and still moves a reported number. The check that
closes the class is the content hash, so the scorers verify each input they
read against ``ARCHIVE_SHA256SUMS.txt``, the index published beside the corpus
volumes and mirrored here.

The index keys are relative to the corpus payload root; the volumes unpack to
several different places under ``data/``, so ``payload_key`` maps a repository
path back to its key. A file that is not in the index, or that hashes
differently, is not the input the frozen outputs were computed from -- whatever
else is true of it. A tree that is missing an indexed file is not the published
tree either, and ``check_tree`` says so.

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


def logical_rel(path, root):
    """The path's position under `root`, *without* following symlinks.

    Resolving first would defeat the purpose. ``check`` is asked whether the
    file at this slot is the published one; if the slot is a symlink to some
    other indexed file, resolving turns the question into "is the target
    published" -- which it is -- and the substitution passes. So the key comes
    from the unresolved path, and a symlink anywhere between the root and the
    file is refused outright: the published corpus contains none, so one here
    means the tree has been rearranged.

    Returns (relative path, None) or (None, reason).
    """
    p = Path(os.path.abspath(str(path)))
    r = Path(os.path.abspath(str(root)))
    try:
        rel = p.relative_to(r)
    except ValueError:
        return None, f"{path} is outside the repository"
    walk = r
    for part in rel.parts:
        walk = walk / part
        if walk.is_symlink():
            return None, (f"{walk.relative_to(r)} is a symlink; the published corpus has "
                          "none, and the index binds a file at its own path")
    return rel, None


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
    rel, why = logical_rel(path, root)
    if why:
        return why
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


def verify_all(root, quiet=False):
    """Check every unpacked corpus file against the index. Returns (ok, missing, bad).

    `sha256sum -c` on the mirrored index does not work, and that is not a defect
    in the index: its keys are relative to the corpus payload root, while the
    twelve volumes unpack to four different places under `data/`. Roughly 3,000
    of the 16,698 keys -- everything under `staging/`, `provenance-inputs/` and
    `aux/` -- cannot resolve from the directory the index sits in. This walks
    the mapping instead, so there is a supported way to check an unpacked
    corpus in one command.
    """
    table = load(root)
    if table is None:
        raise SystemExit(f"{index_path(root)} is missing")
    reverse = {}
    for repo_prefix, payload_prefix in LAYOUT:
        reverse[payload_prefix] = repo_prefix
    ok, missing, bad = 0, [], []
    for key, want in sorted(table.items()):
        top = key.split("/", 1)[0] + "/"
        repo_prefix = reverse.get(top if top in reverse else "")
        rel = key[len(top):] if top in reverse else key
        path = Path(root) / repo_prefix / rel
        if not path.is_file():
            missing.append(key)
            continue
        # A symlink to the right bytes would hash correctly. The published
        # archive has no links, so one here means the tree was rearranged, and
        # the point of this sweep is to attest the archive as published.
        if path.is_symlink() or any((Path(root) / repo_prefix).joinpath(*rel.split("/")[:i + 1]).is_symlink()
                                    for i in range(len(rel.split("/")))):
            bad.append(f"{key} (symlink)")
            continue
        if sha256_file(path) != want:
            bad.append(key)
        else:
            ok += 1
    if not quiet:
        print(f"{ok} verified, {len(missing)} not unpacked, {len(bad)} MISMATCHED")
        for key in bad[:20]:
            print(f"  MISMATCH {key}")
        if missing[:5] and not bad:
            print(f"  (not unpacked, e.g. {', '.join(missing[:3])})")
    return ok, missing, bad


def check_tree(root_dir, root, limit=None):
    """Every file under `root_dir` must be in the index and match it, and every
    indexed file under `root_dir` must be present.

    Both directions matter. An unlisted file was not part of what shipped. A
    listed file that is absent is the case a walk over existing files cannot
    see: a snapshot tree missing one of its files hashes clean on everything
    it still has, and a detector diffing that tree reads the gap as a deletion
    the session performed. So the tree is compared against the index's own
    list of what belongs under it, not only file by file.
    """
    bad = []
    rel, why = logical_rel(root_dir, root)
    if why:
        return [why]
    key = payload_key(rel)
    if key is None:
        return [f"{rel} is not in a directory the corpus volumes unpack into"]
    table = load(root)
    if table is None:
        return [f"the release checksum index {INDEX_NAME} is missing"]
    prefix = key if key == "" or key.endswith("/") else key + "/"
    expected = {k for k in table if k.startswith(prefix)}
    seen = set()
    for path in sorted(Path(root_dir).rglob("*")):
        if path.is_symlink():
            # The published trees are regular files throughout. A link here is a
            # rearranged tree, and rglob would otherwise walk through it.
            bad.append(f"{path} is a symlink; the published corpus has none")
        elif not path.is_file():
            continue
        else:
            why = check(path, root)
            if why:
                bad.append(why)
            else:
                r, _ = logical_rel(path, root)
                seen.add(payload_key(r))
        if limit and len(bad) >= limit:
            return bad
    for k in sorted(expected - seen):
        bad.append(f"{k} is listed in {INDEX_NAME} but absent from the tree")
        if limit and len(bad) >= limit:
            break
    return bad


if __name__ == "__main__":
    import sys as _sys
    _root = Path(__file__).resolve().parents[2]
    if "--verify" in _sys.argv:
        _ok, _missing, _bad = verify_all(_root)
        # --verify alone reports a partial unpack rather than failing it, so a
        # reader can tell "I have not unpacked everything" from "what I have is
        # wrong". --require-complete is the form for CI, which wants one exit
        # code covering both.
        if "--require-complete" in _sys.argv and _missing:
            print(f"  --require-complete: {len(_missing)} indexed files are not unpacked")
            _sys.exit(1)
        _sys.exit(1 if _bad else 0)
    print(f"{__doc__.strip().splitlines()[0]}\n\n"
          f"  python3 {Path(__file__).relative_to(_root)} --verify [--require-complete]\n\n"
          f"index: {index_path(_root)}")
