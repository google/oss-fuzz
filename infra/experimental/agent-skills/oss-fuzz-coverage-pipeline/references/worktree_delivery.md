# Worktree-based delivery for the OSS-Fuzz coverage pipeline

Companion reference for the `oss-fuzz-coverage-pipeline` skill: the marked working area, worktree duo pairs, the temporary copy bridge, the validation loop, rejection, pristine clone removal and the final handover.

## The marked working area

All artefacts live under one clearly marked working area, separate from the main OSS-Fuzz checkout and from any normal clone, with the pristine clones and the worktrees in different directories:

```
<working-area>/                          # for example ~/agent-coverage-work/
  upstream-clones/<project>/             # pristine clones of the default branch (scaffolding only)
  worktrees/oss-fuzz/oss-fuzz-<project>-<suffix>/
  worktrees/upstream/<project>-<suffix>/
  rejected/                              # rejected duo pairs moved here, kept intact
  summary.md                             # the final summary table
```

The concrete paths, the branch names and the base commit SHAs are part of the result: record them in the manifest and the final summary.

## Branch naming and duo pairs

- Clone the upstream default branch (main or master) if a local clone does not already exist, and create worktree branches from it. Clones live under `upstream-clones/` and never under `worktrees/`.
- OSS-Fuzz side branch: `oss-fuzz-<project>-<suffix>`. Upstream side branch: `<project>-<suffix>`. The `<suffix>` (the topic) is identical on both sides and is what pairs them; for example `oss-fuzz-json-c-add-bcf-parser` paired with `json-c-add-bcf-parser`.
- **Always create the duo pair, even when no OSS-Fuzz changes are needed**: all testing goes through the temporary copy bridge, which lives in the OSS-Fuzz side Dockerfile, and the main checkouts must stay clean.

```sh
# OSS-Fuzz side, run from the main OSS-Fuzz checkout:
git worktree add -b oss-fuzz-<project>-<suffix> \
    <working-area>/worktrees/oss-fuzz/oss-fuzz-<project>-<suffix>

# Upstream side, run from the pristine clone of the default branch:
git -C <working-area>/upstream-clones/<project> worktree add -b <project>-<suffix> \
    <working-area>/worktrees/upstream/<project>-<suffix>

# Record the base each branch was created from:
git -C <working-area>/upstream-clones/<project> rev-parse HEAD   # goes into the manifest
```

## Pair grouping per project

A project is delivered through one or more duo pairs:

| Pair type | Contents | Count per project |
|---|---|---|
| Fuzzer pair | A fixed or new harness plus its own corpora, dictionaries and options, plus any build-configuration change that specific harness needs | Zero or more |
| Standalone corpus pair | All corpora, dictionaries and options changes with no fuzzer change | Zero or one, suffix `-corpus-dict-options` |
| Build-fix pair | A general build fix not tied to one fuzzer | Zero or one, suffix `-build-fix` |

A single delivered pair is the minimum bar; develop multiple pairs when worthwhile. Worth is your own judgement, but it must be backed by the written Phase 2 rationale (dark covered lines, security sensitivity, reachability, expected impact), recorded per pair. Do not fragment trivially: corpus, dictionary and option tweaks that are not fuzzer-related always fold into the standalone pair.

Each pair gets its own worktrees, bridge blocks, validation, fix budget and summary row. A project counts as delivered when at least one of its pairs is delivered; rejected pairs are still recorded individually.

## Build-fix dependency protocol (main build failures only)

This protocol applies when the **main fuzzer build** fails. Coverage or introspector build failures do not trigger it; they follow the exemption rule (missing corpora or OOM/timeout) plus the historical-report date walk-back.

1. **Fix pair first**: create the `-build-fix` duo pair from master, fix and validate it. It is a deliverable in its own right.
2. **Dependent pairs copy the fix in for testing only**: every later fuzzer or corpora pair on the project is created from master as normal, then the build-fix changes are copied into its worktree(s) as a testing scaffold so the project builds and the gates can run. Record `tested-with: <project>-build-fix` in the manifest and summary row; the user's commit order is the fix branch first.
3. **Remove the copied fix after conclusion**, whether the pair is delivered or rejected. The fix lives exclusively in the build-fix pair; a dependent pair's final diff contains only its own work.

### Copying the fix in, and removing it selectively

At copy time, record the file list and **snapshot the fix-affected files as copied**. Do the dependent work on top. At removal time, for each fix-affected file:

- if the dependent work never touched the file, restore the branch-base version (the simple case);
- if it did (for example both edited the same Makefile), removal is surgical: compute the delta from the fix snapshot to the current file (exactly the dependent's own edits), restore the branch-base version, then re-apply that delta onto it. Result: base plus own work, fix gone.

Verification after removal is mandatory: re-diff the worktree against the branch base and confirm only the dependent's own work remains. If an edit is genuinely entangled with the fix on the same lines and cannot be separated, preserve the dependent's functional intent, keep the minimal necessary fix fragment, and flag it explicitly in the report and summary (never keep fix content silently). This is safe in practice because the fix branch is committed first.

Rejected dependent pairs: remove the copied fix changes first, then move the pair to the rejected area.

## Never commit, never push, never stage by default

Leave every change as plain working-tree files (modified or untracked). Commit and push are strictly forbidden. Staging is skipped unless it is absolutely necessary for the task, and any unavoidable staging is recorded with a reason in the report. If a commit happens by accident, stop and notify the user immediately; never try to quietly undo it.

## The temporary copy bridge

The project Dockerfile normally clones the upstream source at build time, so testing upstream changes would normally require a merge. Since commits are forbidden, simulate the merge at Docker build time instead:

1. Copy the changed upstream files into a clearly marked bridge staging folder inside the OSS-Fuzz worktree, for example `projects/<project>/bridge/<suffix>/`, mirroring their upstream layout. The staging folder is part of the working-tree result.
2. Add a tagged block to the project Dockerfile, placed after the normal clone or download step, that copies the bridged files over the cloned source:

```dockerfile
# OSS-FUZZ-AGENT-BRIDGE:BEGIN <project>-<suffix>
COPY bridge/<suffix>/fuzz/ $SRC/<project>/fuzz/
# OSS-FUZZ-AGENT-BRIDGE:END <project>-<suffix>
```

3. Adjust the COPY source paths to whatever the Docker build context actually provides (verify on the first build; the project's existing `COPY build.sh $SRC/` lines show the convention), and make sure the destination matches where `build.sh` expects the source (`$SRC/<project>`).
4. Never remove or comment out bridge blocks automatically: they are part of the delivered result and are removed manually by the user only after the real upstream merge has happened.

Reading, cloning and inspecting upstream code locally is fine as usual; only validation builds must go through `python3 infra/helper.py`.

## The validation loop (per duo pair)

Run pairs one at a time (builds of the same project share Docker image names), from the OSS-Fuzz worktree root, always through `infra/helper.py`:

```sh
# 1. Build the declared matrix from projects/<project>/project.yaml:
python3 infra/helper.py build_fuzzers --sanitizer address <project>
python3 infra/helper.py build_fuzzers --sanitizer undefined <project>    # as declared
python3 infra/helper.py build_fuzzers --sanitizer coverage <project>
#    plus engines where declared, for example: --engine afl

# 2. Mandatory per-fuzzer gate, for every new or updated fuzzer:
python3 infra/helper.py check_build <project> <fuzzer_name>

# 3. Fuzzing-quality gate (thresholds below):
python3 infra/helper.py run_fuzzer <project> <fuzzer_name> -- \
    -max_total_time=120 -timeout=25 -rss_limit_mb=2560
```

Quality thresholds, which apply on top of `check_build` passing, and to corpora, dictionaries and option changes as well as new harnesses:

- minimum run 120 seconds per target, 300 seconds for corpus-heavy changes;
- a crash within the first 60 seconds is a fast-crash failure;
- coverage must keep increasing: no growth in the final half of the run counts as stale (compare the `cov:` figures between libFuzzer checkpoints in the run log);
- record the evidence (run logs and the coverage trend) in the per-project report.

These libFuzzer-style flags apply to every OSS-Fuzz engine: Jazzer, Atheris and Go-native fuzzing all wrap libFuzzer.

### Coverage delta, like-for-like

1. Baseline before any change: build the coverage configuration in a clean state and run `python3 infra/helper.py coverage <project>`; copy the resulting `summary.json` to a scratch directory outside the build tree.
2. Candidate: identical flags and identical corpus source in the duo-pair worktree; save its `summary.json` the same way.
3. Compare per-file `lines.covered` counts on project-own paths: targeted files must gain covered lines, and no other project-own file may lose them. With an identical corpus, locally covered lines can only come from your change, which is what makes small deltas trustworthy.
4. Never compare a fresh local number with a production report; local short-run coverage is always lower (see `code_coverage.md` section 7 and `structured_seed_generation.md`).

### Failure triage, fix budget and rejection

| Symptom | Likely cause | Action |
|---|---|---|
| Compile failure in the pair | Harness or build-configuration defect | Fix; counts against the budget |
| Crash immediately, even on trivial input | Harness defect | Fix the harness; re-run |
| Crash on mutated input only, reproducible | Possibly a real bug | Minimise, verify against latest upstream, document as a finding with a reproducer |
| Timeout | Pathologically slow path or loop | Bound input, stream with limits, or justify a higher limit in the report |
| OOM | Unbounded allocation from fuzzed lengths | Bound allocations in the harness |
| Leak report | Resource owned per iteration | Fix the harness to free or reuse; if the library itself leaks, document it |
| Stale or non-growing coverage | Weak corpus, weak harness or wrong target | Seeds, dictionaries or harness redesign |

The fix budget is **3 rounds** per gate failure: fix, retest, and at most three attempts. A pair still failing after the third round (compile failure, staleness, early crash or any other gate) is rejected. Rejected pairs are **moved, never deleted**, so they can be attempted again later:

```sh
git -C <main-oss-fuzz-checkout> worktree move \
    <working-area>/worktrees/oss-fuzz/oss-fuzz-<project>-<suffix> \
    <working-area>/rejected/oss-fuzz-<project>-<suffix>

git -C <working-area>/upstream-clones/<project> worktree move \
    <working-area>/worktrees/upstream/<project>-<suffix> \
    <working-area>/rejected/<project>-<suffix>
```

Use `git worktree move` (not a plain `mv`) so the worktrees stay functional with their branch refs intact. The summary records the failure reason, what was attempted across the rounds, and the new rejected-area paths.

## Pristine clone removal

The `upstream-clones/` repositories are scaffolding: keep them while work is in progress, because branch creation, diffs and base tracking need them. Record each branch's base commit SHA in the manifest before making changes. Remove a clone only when removal is safe, normally at the very end after the user has committed the work or confirmed the plain files suffice; with nothing ever committed, deleting a clone leaves the worktree files intact but orphans their git links and branch refs, which is exactly why the base SHAs must already be recorded. If removal is not safe at handover, keep the clone and document the exact removal command instead. Never risk the work to satisfy the cleanup preference.

## Final summary and handover

Write `summary.md` at the working-area root with one markdown table covering everything that was selected:

| project | language | status | duo branches | depends on | worktree paths | summary of work | coverage delta | reason |
|---|---|---|---|---|---|---|---|---|

- status is `delivered`, `rejected (moved to rejected area)` or `skipped/blocked`;
- depends on records `tested-with: <project>-build-fix` for pairs validated with a copied build fix; commit those fix branches first;
- skipped rows carry the concrete reason, for example `blocked(upstream-archived)`;
- rejected rows carry the failure reason and what was attempted;
- delivered rows summarise the work (harnesses, corpora, dictionaries, build configuration, bridges) and the like-for-like coverage delta.

The complete handover is: the surviving duo pairs in `worktrees/`, the rejected pairs in `rejected/`, `summary.md`, the per-project reports under `projects/<project>/` in the main checkout, the manifest, the recorded base SHAs, and the next actions for the user: review, commit the upstream branch first and then the OSS-Fuzz branch, remove the bridge blocks and staging folders, then move or remove worktrees and pristine clones as appropriate.
