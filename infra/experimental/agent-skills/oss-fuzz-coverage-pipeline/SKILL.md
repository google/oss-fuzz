---
name: oss-fuzz-coverage-pipeline
description: >-
  Use this skill to bring a project that is already integrated into OSS-Fuzz (C/C++, Go, Rust, JVM or Python) to a well-fuzzed state: fix broken builds, triage live coverage, improve fuzz targets, corpora and dictionaries, and deliver the work as worktree branch duo pairs. Never commits, never pushes and by default never stages. Selects projects by name, glob pattern or all projects, verifies upstream viability from the Dockerfile, auto-detects the language from project.yaml and activates the matching language skill. Processes one project at a time via a run manifest.
---

# OSS-Fuzz coverage pipeline

End-to-end pipeline for an already-integrated OSS-Fuzz project (any language with a dedicated fuzzing skill) whose fuzzing is broken or weak. The goal is that the project's own security-sensitive code is reachable and actually exercised by fuzz targets, and that the work is delivered as worktree branch duo pairs that a human can review, commit and push.

This skill is a process wrapper. It defines what to do and in which order; it deliberately does not re-teach the underlying knowledge. While working through the phases you MUST also use:

- **oss-fuzz-engineer**, always: OSS-Fuzz infrastructure, builds, `infra/helper.py`, project layout, public build status and coverage data.
- the **language-appropriate fuzzing skill**, auto-determined from each project's `project.yaml` `language` field, which is the sole source of truth for the language. The Dockerfile base image is toolchain compatibility only and is never a language signal: a C++ project with a Rust module may legitimately sit on the rust base image.

| `project.yaml` language | Sub-skill to activate |
|---|---|
| `c`, `c++`, or missing | **fuzzing-memory-unsafe-expert** |
| `go` | **fuzzing-go-expert** |
| `rust` | **fuzzing-rust-expert** |
| `jvm` | **fuzzing-jvm-expert** |
| `python` | **fuzzing-python-expert** |
| other (javascript, swift, ruby, ...) | none dedicated: rely on oss-fuzz-engineer, or scope the run with `--language` |

- **fuzzing-coverage-targeting**, in Phases 2, 3 and 5: which targets are worth harnessing and what shape each harness takes (worth model, dark-region taxonomy, harness patterns, portfolio cap and overlap rules).

plus their references (`code_coverage.md`, `structured_seed_generation.md`, `helper.md`, `oss_fuzz_project_structure.md`) where pointed to below.

## Hard guardrails

1. **Never `git commit` and never `git push`, in either repository: this is strictly forbidden.** Staging (`git add`) is also skipped by default. Leave changes as plain working-tree files (modified or untracked), and stage only when it is absolutely necessary for the task, recording why in the report. If a commit happens by accident, stop immediately and notify the user; never try to quietly undo it.
2. **Every build, check, run and coverage measurement goes through `python3 infra/helper.py`** inside the OSS-Fuzz Docker environment. Never validate with bare local toolchains (direct clang, cmake, cargo, gradle and the like). Reading and inspecting cloned source locally is fine.
3. The worktree duo pairs hold the only copies of the work. Do not run destructive git commands inside a worktree, and do not delete worktrees; rejected pairs are moved to the rejected area, never deleted.
4. Every claim of improvement must be backed by a measurement: build success, fuzzer run output or coverage numbers. No measurement, no claim.
5. **Fresh data on every run**: whenever this skill determines any project data, treat it as a new check and never rely on memory from previous runs. Reread `project.yaml` (language, sanitizers, engines, `main_repo`), the Dockerfile, the build status, the coverage report pointers and the upstream state on every run. If a project's language changed since an earlier run (for example C++ to Rust), the new run must see the new value and select the sub-skill accordingly. The manifest carries process state (what is done and pending), not world facts: when a fresh read contradicts something recorded earlier, the fresh read wins and the manifest row is corrected. This matters most on reruns: a project may have been updated by a previous batch of duo pairs (merged and since picked up by production), so earlier coverage data, target lists and assumptions no longer hold. A second run re-derives everything from fresh data and treats earlier findings, including which code was dark or already covered, as history rather than truth.
6. **Upstream product code is off-limits**: never modify the upstream project's own source code. Bugs in it are findings (documented, filed by the user), never fixes by the agent. The only permitted upstream changes are: fuzzers (harnesses and their corpora, dictionaries and options), fuzz build configuration (wiring the targets into the build), and additions guarded by the `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` macro, which is the sole sanctioned product-code edit (the macro is set in OSS-Fuzz builds and is the standard way to make behaviour fuzz-friendly without affecting production). If product code gets modified by accident, stop immediately and notify, never quietly undo. The OSS-Fuzz repo side (Dockerfile, `build.sh`, `project.yaml`) is not affected by this rule.
7. **Classify every post-build crash; never silence**: a crash, memleak, OOM or timeout after a successful build, whether it surfaces in `check_build` or in the fuzzing runs, is never an automatic failure: classify it first (procedure in the worktree reference). Fuzzer faults consume the fix budget; real findings keep the pair delivered with the discovery marked and consume nothing. Never introduce new silencing (no leak-detection muting, no suppression flags or files, no raised limits to dodge a failure). Pre-existing suppressions in the existing integration or existing fuzzers are honoured unchanged: carried over for new and fixed fuzzers, neither removed nor widened, and only what they already cover is out of scope.
8. **Precedence**: these guardrails and this skill's rules override any conflicting guidance in the sub-skills; the sub-skills supply craft and knowledge within these bounds.

## Deliverables

The result of a run, all inside the marked working area (see [references/worktree_delivery.md](references/worktree_delivery.md)):

1. The list of surviving worktree branch duo pairs: OSS-Fuzz side `oss-fuzz-<project>-<suffix>`, upstream side `<project>-<suffix>`, with their worktree paths and base commit SHAs recorded. A project may contribute several pairs (fuzzer pairs, a standalone corpus pair, a build-fix pair), grouped per the Phase 4 rules.
2. A final summary in markdown table form, one row per duo pair: project, language, duo branches, depends-on, worktree paths, summary of work, coverage delta, status.
3. Skipped or unprocessable projects listed in the same summary with the concrete reason.
4. Rejected duo pairs (still failing after the fix budget) moved into the rejected area, kept intact, and marked clearly in the summary with the failure reason and what was attempted.

## The pipeline

Work the phases strictly in order, and conclude each phase in writing (manifest and final report) before starting the next.

### Phase 0: Select projects and verify upstream viability

Selection uses the deterministic selector bundled with this skill (`scripts/select_projects.sh` next to this SKILL.md); output is `project<TAB>language`, one per line, where the language is the one **declared** in `project.yaml` (a missing field is the legacy `c++` default), not verified against the source, and the Dockerfile base image is never a language signal. Activate the matching sub-skill per the mapping above. Reread this data on every run, even for projects seen before: a project whose `project.yaml` changed since an earlier run (for example its language moving from C++ to Rust) is treated according to the fresh values, never the previous run's memory.

```sh
scripts/select_projects.sh '*'                      # all projects (any language)
scripts/select_projects.sh 'lib*' 'json*'           # glob subset
scripts/select_projects.sh --language c,c++ '*'     # scope by language
scripts/select_projects.sh --broken --limit 20 '*'  # broken builds first
scripts/select_projects.sh --exclude 'curl,wget' '*'
```

Before doing any real work on a selected project, verify the upstream is viable. **Never trust `main_repo` in project.yaml: it may be missing or wrong. Always read the project's Dockerfile to find what is actually cloned or downloaded** (a git clone, a downloaded tarball, or svn), and run the checks against that real location:

- repository marked archived: stop and notify, manifest `blocked(upstream-archived)`;
- no commits for 24 months or more: stop and notify, `blocked(upstream-inactive)`;
- repository moved or abandoned (moved redirects, "we moved" banners, homepage pointing elsewhere while the integration still points at the dead location): stop and notify, `blocked(upstream-moved)`, noting the new location if it is discoverable, but never chase it automatically;
- source is not a git repository (tarball or svn): stop and notify, `blocked(upstream-not-git)`.

Stopping is mandatory in every case; it is never agent judgement. Then create (or resume) the per-project manifest fragment at `build/coverage-pipeline/manifest/<project>.md` (one authoritative file per project; the batch driver merges a combined `manifest.md` view after the run; a legacy single-file manifest is history):

| project | language | status | duo branches | worktree paths | base SHAs | report | notes |
|---|---|---|---|---|---|---|---|

Statuses: `selected`, `viable`, `builds-green`, `triaged`, `improved`, `validated`, `delivered`, `rejected`, `no-worthy-targets`, `deferred(budget)`, or `blocked(<reason>)`. Update the row at the end of every phase; a fresh session resumes work by reading the manifest. When a project yields several pairs, give each pair its own manifest row (same project, its own suffix and duo branches), with a `tested-with: <project>-build-fix` note in the notes column when it depends on the build fix. The language column starts as the declared language; after a mid-run language switch (see Phase 2), record it as `declared(X)/actual(Y)`. A rerun after a previous delivered batch starts fresh rows (or a new dated section) and treats earlier rows as history only; previously rejected pairs may be deliberately retried against the new state. Sessions exit via the exit protocol: before exiting, a session updates the manifest with the pairs delivered, the remaining ranked targets with rationales, and a terminal stop line `STOP: <project> : <worth-exhausted|cap-reached|no-worthy-targets|budget-exhausted|blocked(...)>`; running out of context means checkpointing progress and deferred entries, never a shallow wrap-up. Declaring `no-worthy-targets` requires genuine judgement and proof: a per-region worth analysis with the top rejected candidate regions listed, their numbers, and why each fails the worth model; it is never a quick early exit and is reviewed as seriously as a failure.

Multi-project discipline: **serialise only real `infra/helper.py` executions** (Docker builds, checks and runs: one project at a time, since image names collide). Analysis (triage, coverage study) and worktree/fuzzer generation may proceed in parallel across projects and pairs. With 1,300+ projects in OSS-Fuzz (~600 C/C++), prefer prioritised subsets over `*`: broken builds first (fast wins that also unlock coverage data), then the lowest own-code coverage on security-sensitive surface.

### Phase 1: Builds, mandatory and optional fixes

Get the builds into a state where analysis is possible, always via `infra/helper.py`:

```sh
python3 infra/helper.py build_fuzzers <project>
python3 infra/helper.py build_fuzzers --sanitizer coverage <project>
python3 infra/helper.py build_fuzzers --sanitizer introspector <project>
python3 infra/helper.py check_build <project>
```

- The main fuzzer build fix is **always mandatory**: minimal, targeted changes only. When the main build is broken, the fix becomes its own `-build-fix` duo pair, created and validated before any dependent pair (see Phase 4 and the worktree reference). An upstream-side build fix must itself stay within the allowed upstream categories (fuzzers, fuzz build configuration, the `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` macro); if the build can only be repaired by changing product code, stop and notify `blocked(product-code-fix-needed)`.
- Coverage and introspector build fixes are expected, but are **optional when the failure cause is missing corpora or an OOM/timeout**. Record the exemption with evidence, then proceed using the most recent successful historical report (Phase 2 date walk-back). These failures do not trigger the build-fix protocol.
- A `check_build` failure caused by a crash is classified like any other post-build crash (see the worktree reference): it is a harness defect only when the crash is the fuzzer's fault; a crash classified as a real finding still passes this gate with the discovery marked.
- The full `helper.py introspector` chain is heavy; reserve it for when an actual Introspector report is needed (see `code_coverage.md` section 7).

### Phase 2: Triage live coverage on the project's own code

Canonical live coverage references (resolve `YYYYMMDD` with the walk-back rule below):

- overall report: `https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports/<YYYYMMDD>/linux/report.html`
- per fuzz target: `https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports-by-target/<YYYYMMDD>/<fuzzer_binary_name>/linux/report.html` (use it to attribute dark code to specific harnesses)
- parse the machine-readable `summary.json` siblings at the same paths; the HTML is the human view.
- reachability detail: `https://introspector.oss-fuzz.com/project-profile?project=<project>`

**Date walk-back**: coverage and introspector builds sometimes fail (cross-check the build status on introspector.oss-fuzz.com), so the latest date may have no report. Resolve the date by walking backwards day by day, at most 30 days, until a report exists, and record the date actually used.

Produce a written target list via **fuzzing-coverage-targeting** (worth model, dark-region taxonomy, ranked multi-target list) and initialise the run's coverage ledger from the per-target baseline reports (`reports-by-target`); do not improvise targets later. **Plan first, on disk**: persist the complete ranked list (every candidate pair with its suffix and worth rationale) into the manifest before any Phase 3 or 4 work, so continuation sessions and deferral recording always have the full picture. On a rerun of a project previously worked on, do not reuse the earlier target list: re-derive it from the fresh reports, because the previous batch of pairs may have shifted coverage (previously dark targets may now be covered and must be dropped; still-dark ones are re-attempted).

**Verify the declared language while analysing**: while reading the source tree, build scripts and existing harnesses, check that the declared language (project.yaml) matches reality. If it does not, switch the active language sub-skill to the matching one and **continue in all cases**, even when the actual language falls outside the run's `--language` filter, recording the discrepancy: manifest `declared(X)/actual(Y)`, evidence in the report, actual language in the summary with the declared one noted. For mixed-language projects, the project-level language stays the corrected declared one, but a pair whose harness targets a module in a different language may activate that language's skill for that pair, noted in the pair's row.

1. Filter to the project's own code (paths under `/src/<project>/`), dropping system headers, vendored dependencies and test files; rank by dark covered-line counts, not percentages.
2. **Verify build scope before trusting any percentage**: a high percentage can be an artefact of a partial build. Compare the upstream source tree's modules against the files present in the report; flag any module that exists upstream but is absent from the build, and treat "well covered" claims as invalid until the scope is verified. Enabling missing modules is a valid Phase 3 action.
3. Cross-check Fuzz Introspector for **statically reached but dynamically unreached** functions: reachable from harnesses but never hit in the coverage report. These are prime targets (seeds, dictionaries and harness adjustment to convert static reachability into real coverage).
4. Classify each candidate security-sensitive or not; the point is attack surface, not raw percentage. In scope: file-format parsers and loaders, wire-protocol handlers, deserialisers, decompression and codec paths, custom string and number parsing on untrusted data, path and filename handling, IPC message handling, state machines driven by untrusted input, crypto primitives. Out of scope, usually: diagnostic logging and printf-style output, UI code, config writing, build tooling and test helpers, unless untrusted data reaches them.
5. Record per target: the metric that flagged it, whether it is seed-limited or harness-limited, and the expected bug class.

### Phase 3: Act on the targets

| Signal | Action |
|---|---|
| File dark because no harness reaches it | **New harness** (harness-limited) |
| Harness reaches it but the corpus never gets deep | **Seeds** (structured generation) and/or **dictionary** |
| Statically reached but dynamically unreached | **Seeds and dictionaries first**, then harness adjustment (state setup, enabling the path) |
| Path disabled or held fixed in the harness | **Fix the harness** (fuzz what the attacker controls) |
| Module missing from the build entirely | **Fix the build configuration** to compile it in |
| Build configuration hides code from fuzzing | **Fix build configuration** (flags, `$LIB_FUZZING_ENGINE` wiring) |

Choose the harness shape per **fuzzing-coverage-targeting**'s pattern catalogue (round-trip, property, stateful sequence, option-matrix, component-API or classic parser), then write and validate it per the language-appropriate skill from the mapping at the top of this skill (threat model first, typed input as the sub-skill prescribes, dictionaries and seed corpora into `$OUT`, and study the project's own existing harnesses for conventions). Never target code that the production corpus already covers well. Fuzz-unfriendly behaviour inside product code (non-determinism, network, real-time limits) is handled by adding `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`-guarded code, never by editing the product code unguarded.

### Phase 4: Stage in worktree duo pairs

Follow [references/worktree_delivery.md](references/worktree_delivery.md) precisely. Essentials:

- A **duo pair is always created**, even when no OSS-Fuzz changes are needed, because all testing goes through the temporary copy bridge in the OSS-Fuzz side Dockerfile, and the main checkouts must stay clean.
- Branches: OSS-Fuzz side `oss-fuzz-<project>-<suffix>`, upstream side `<project>-<suffix>`; the identical `<suffix>` is what pairs them.
- The pristine main/master clones live under `upstream-clones/`, the worktrees under `worktrees/`, inside one marked working area whose concrete paths are reported as part of the result.
- The **temporary copy bridge** copies the changed upstream files over the cloned source at Docker build time, simulating a merged upstream without any commits: tagged BEGIN/END blocks in the Dockerfile plus a marked bridge staging folder inside the OSS-Fuzz worktree. Never remove bridges automatically; they are part of the delivered result.
- Leave changes as plain working-tree files: no staging by default, no commits, no pushes, ever.

**Grouping rules, one project and several pairs:**

- Work each project's ranked target list **top-down until the rules are exhausted**: multiple pairs per project are the norm whenever worth remains, up to the cap. A single delivered pair is the floor for the project's delivered status, never a stopping point, and worth is measured per project, never compared across projects (one pair per project is a batch anti-pattern). Stop only on worth exhaustion (remaining marginal worth genuinely low, documented with numbers), the 5-pair cap (default, prompt-adjustable; improvement pairs, with a `-build-fix` pair not counting against it), or genuine budget exhaustion; budget-deferred targets are recorded as "pair N of project X: worth rationale written, not yet attempted", never as worth decisions. A project with genuinely no worthy targets is marked `no-worthy-targets` with its triage evidence; never invent a trivial pair to meet the floor.
- A pair that fixes or adds a fuzzer **carries that fuzzer's corpora, dictionaries and options in the same pair**: a harness never ships separately from its own seeds and settings.
- All remaining corpora, dictionaries and options changes with no fuzzer change are consolidated into a **single standalone pair** with the suffix `-corpus-dict-options`.
- A general build fix not tied to one fuzzer gets its own pair with the suffix `-build-fix`; build-configuration changes a specific fuzzer needs ride inside that fuzzer's pair.

For a project whose main build was failing, the build-fix protocol in [references/worktree_delivery.md](references/worktree_delivery.md) applies: the fix pair is created and validated first, and every later pair copies the fix in purely as a testing scaffold, removing it again after conclusion.

### Phase 5: Validate, reject or deliver

Validate each duo pair independently and one at a time, always through `infra/helper.py`:

1. **Build matrix**: read `sanitizers:` and `fuzzing_engines:` from `projects/<project>/project.yaml` and validate every declared configuration (for example `--sanitizer address`, `undefined`, `memory`, and engines such as `--engine afl` where declared).
2. **Per-fuzzer gate (mandatory)**: `build_fuzzers` succeeds, and `check_build` passes for every new or updated fuzzer specifically, not just project-wide, **or its failure is solely attributable to a crash classified as a real finding** (documented with a reproducer and marked).
3. **Fuzzing-quality gate (beyond check_build)**: for every new or updated fuzzer, corpus, dictionary or option change, actually fuzz and require **no crash, leak, OOM or timeout attributable to the fuzzer** (nothing within the first 60 seconds) and coverage that keeps increasing rather than going stale (no growth in the final half of the run counts as stale). Minimum run 120 seconds per target, 300 seconds for corpus-heavy changes. Every post-build crash goes through the classification procedure in the worktree reference: real findings keep the pair delivered with the discovery marked, fuzzer faults consume the fix budget, and a crash rooted in product code is always a finding, never a product-code patch.
4. **Coverage growth, per fuzzer (fast path)**: for every fuzzer created or modified, compare the start and end `cov:` of its own quality-gate run: coverage must increase over the run, with `ft:` (features) and corpus size as supporting increase signals. No baseline build, no cross-build comparison and no separate coverage build are needed; a `--sanitizer coverage` build remains only as the per-file fallback for file-level numbers the report must show or marginal overlap decisions (see the worktree reference). Update the run's coverage ledger with the measured numbers and compute the pair's **incremental** contribution against what existing fuzzers and previously accepted pairs already cover: a pair whose gains mostly overlap is redesigned toward different dark regions, folded into standalone corpus work, or dropped, with the numbers recorded (rules from fuzzing-coverage-targeting).
5. **Fix budget of 3 rounds**: fix, retest, and at most three attempts per gate failure. A pair still failing after the third round (compile failure, staleness, early crash or any other gate) is **rejected**: move both worktrees into the rejected area with `git worktree move` (never delete), keep the branches, and record the failure reason, what was attempted and the new paths.
6. Deliver: remove any copied build-fix changes and verify the remaining diff is purely this pair's own work (see the worktree reference), finalise the per-project report and the manifest row, and add the row to the final summary table.
7. **Exit protocol and relay**: before a session exits, update the manifest (pairs delivered, remaining ranked targets with rationales, terminal `STOP:` line per the format in Phase 0); when context or time runs low, checkpoint cleanly rather than wrapping up shallowly, because the batch driver relaunches continuation sessions until a terminal stop or the session cap.

Portfolio loop: work each project's ranked list top-down to the **cap of 5 pairs per project** by default (prompt-adjustable; improvement pairs, with a `-build-fix` pair not counting against it), stopping earlier only on documented worth exhaustion (remaining marginal worth genuinely low, with numbers), and recording genuine budget exhaustion as deferred entries ("pair N of project X: worth rationale written, not yet attempted"), never as worth decisions. Disk discipline: check available disk before builds; when low, stop cleanly with a `budget-exhausted (disk)` stop and deferred entries rather than continuing.

## Definition of done

- [ ] All mandatory builds green from the OSS-Fuzz worktree; per-fuzzer `check_build` passes (or fails solely due to a marked real finding).
- [ ] Quality gate clean for every new or changed target: 120 s minimum, nothing fuzzer-attributable (crash, leak, OOM, timeout) within the first 60 seconds, no staleness; real findings excepted and marked.
- [ ] Coverage: documented gains on targeted files and zero digression on other project-own files (like-for-like measurement).
- [ ] Duo pairs hold plain working-tree changes; nothing staged (unless justified and recorded), nothing committed, nothing pushed.
- [ ] Grouping respected: fuzzer pairs carry their own corpora, dictionaries and options; standalone corpus work sits in one pair; dependent pairs have their copied build-fix changes removed and verified.
- [ ] Portfolio respected: ranked multi-target selection via fuzzing-coverage-targeting, incremental worth and overlap rule applied, cap honoured (default 5 pairs per project unless the user's prompt overrides it).
- [ ] Upstream diffs contain only allowed changes: fuzzers with their corpora, dictionaries and options, fuzz build configuration, and `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`-guarded additions; no product code touched.
- [ ] Bridges present and tagged; rejected pairs moved to the rejected area (not deleted); skipped projects recorded with reasons.
- [ ] Final summary table complete (delivered, rejected and skipped), per-project reports written, manifest rows final.
