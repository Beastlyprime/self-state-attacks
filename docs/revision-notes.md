# Revision notes

What changed in this release after it was first published, and why. The
reproduction entry points ([`REPRODUCE.md`](../REPRODUCE.md), [`results.md`](results.md))
describe the release as it is; this file records how it got there, so that a
reader comparing an earlier download against the current one can see what moved.
No reported number changed in any of these revisions except where stated.

Dates are commit dates on the public repository.

## 2026-09-02 — release audit

- **Corpus totals corrected.** The archive is 16,698 files / 19,478,773,704
  bytes unpacked, 3,047,989,793 bytes compressed in twelve volumes. Earlier
  figures in the README were from a pre-redaction build.
- **Table 9 made recomputable.** `p5_analyze.py` reads its 123 inputs from the
  `provenance-inputs` volume, unpacked to `data/provenance/inputs/`, and
  regenerates `P5_NAMEABILITY_ATTRIBUTION_REPORT.json` byte-for-byte. The `.md`
  beside it is a frozen narrative the script does not write.
- **Table 9's clean side described correctly.** The two populations are equal
  in size (21 and 21) and drawn from the same task family; they are not a
  pairing assignment. A strict one-to-one matching completes at most 19 pairs.
  The cells are marginal counts over each side, so no number moved; the paper's
  "task-matched" wording is an arXiv revision item recorded in `results.md`. The
  report's `population_relation` block, its field names and its narrative were
  aligned with this over three later commits (2026-09-05 and 2026-09-06),
  including removing a 20-run four-detector comparison whose source file is not
  in the release.
- **Section 5.2.** Substrate A of the supervised arm recomputes exactly from
  the corpus. Substrate B's shipped AUCs (.4991 / .4915) do not: the original
  selector was an unordered glob over a tree that held several distinct copies
  of some streams, and the copy it read was not recorded. The recomputed block
  (.5123 / .3837) carries a `stream_selection` map and is written to a
  `*.recomputed.json`; the shipped file is untouched. An interim version of
  `results.md` listed a third pair (.538 / .471) from a development tree with no
  selection map behind it; that figure was withdrawn.
- **Falco.** The 55 attack decisions reassemble from the three published replay
  results in `tier_a`; the 60 clean decisions are carried forward from the
  shipped file because the held-out replay's raw output was never archived.

## 2026-09-03 — the C520 pair

`tier_b/*_lockedpop_cseries` and `tier_c` shipped both halves of
`C520_w3_alert_webhook_runbook` from a `grok-4.6` re-collection that shares the
run id with the `gemini-3-flash` execution the published population is defined
over. The published rows were scored from the gemini execution. The gemini
attack, twin and SCAP captures replaced the grok ones, and the two acquisition
manifests that recorded the grok source paths (`manifests/cseries11_source_paths.json`,
`manifests/scap_targets.json`) were corrected. With this substitution
substrate A recomputes exactly. An earlier version of `results.md` attributed
the substrate A discrepancy to three twins with zero-byte libsinsp streams in
the `p2_mass_attack_lane2` trees; those files are empty there, but the scorer
read the complete copies in `staging` first, so they were not the cause.

## 2026-09-04 — the eleven attack graphs, and input verification

- **Eleven W3 C-series attack trees were symlinks.** The first `staging` volume
  carried them as absolute symlinks into a path that exists only on the
  collection host, so they resolved there and dangled everywhere else, and
  were covered by no checksum. The same eleven trees are published as regular
  files under `tier_b/attacks_lockedpop_cseries`, byte-identical on every
  stream the scorers read; the symlinks were removed and the scorers fall back
  from `staging` to the attack pools. The archive now contains no symlinks.
- **Population gates.** With the trees dangling, `score_ours_3pool.py`
  evaluated 12 of 23 definable attacks and overwrote its frozen output with the
  smaller number, exit 0. It and `score_stide_3pool.py` now require their full
  populations before writing.
- **Content binding.** A gate that asks whether a file is present passes a file
  that is present and wrong: a blanked stream, a stream from another run, or a
  stream truncated to its first record all parse and all move a reported count.
  The scorers therefore hash every input they read against
  `ARCHIVE_SHA256SUMS.txt`, the release index mirrored at
  `data/corpus-manifests/`, and refuse before writing on any difference;
  `corpus_index.py --verify` checks a whole unpacked corpus the same way. The
  run-id binding is kept for the diagnostics it gives.
- **Test suite.** `REPRODUCE.md` states what a run produces: 585 collected,
  seven failing on unshipped intermediates, one timing-dependent.

## 2026-09-05 — admission evidence, toolchain, symlink slots

- **Section 4.4 evidence recovered.** The per-run collector health records and
  freeze gates for all 236 clean runs were recovered from the collection host
  and published under `tier_a/clean_admission/`; `check_admission.py`
  recomputes them and states its coverage: drops, overflows, non-emptiness and
  both freeze gates for 236/236, the `= 1.0` resolution rate for the 100 runs
  whose readiness record survives (80 hash-matched to the freeze), the
  `>= 0.95` gate for the other 136. The paper's all-236 `= 1.0` sentence is an
  arXiv revision item. An earlier version of `results.md` pointed at the
  split manifest's `anti_leakage_asserts` for these quantities; those are
  population counts and carry none of them.
- **Detector runtimes published as recipes.** The AIDE and UNICORN Dockerfiles
  and the upstream URLs and commits for AIDE, the three `crimson-unicorn`
  repositories and `LID-DS/LID-DS` are in `data/detection/toolchain/`. STIDE
  reproduces byte-for-byte once its checkout exists; AIDE and UNICORN can be
  built and run but are not byte-reproducible.
- **`corpus_index.check()` resolved symlinks before the lookup**, so a slot
  symlinked to another indexed file passed. It now keys on the unresolved path
  and refuses any symlink between the repository root and the file.
- **Level 1 exception stated.** `REPRODUCE.md`'s level table carries the
  section 4.4 exception rather than claiming every number is checkable.

## 2026-09-06 — Table 15 and the AIDE pre-check

- **`p4_recovery_cost.py` accepted whatever was unpacked.** With one training
  session and an empty held-out tier it exited 0 and overwrote the Table 15
  result with a one-run population. It now iterates the 236 run ids of the
  frozen split, refuses on any missing or extra directory, binds each record
  to its run id, and hashes each stream against the release index. Table 15
  joins Table 9, B1/B2 and STIDE as an output that recomputes byte-for-byte,
  delete-first, from the corpus alone.
- **`score_aide_3pool.py`** verifies every snapshot tree against the index
  before the container runs on any of them.
- **Process identifiers removed** from published files: the split manifest's
  `design` string and four acquisition scripts' `SSH_AUTH_SOCK` value named the
  tooling used during the release process. The manifest change alters no
  population, assertion or number; `FINAL_3POOL_REPORT.json` re-derives from it
  unchanged apart from the same string.
- **This file.** The audit history that had accumulated in `results.md` and
  `REPRODUCE.md` was moved here.
