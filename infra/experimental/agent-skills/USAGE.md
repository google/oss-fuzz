# OSS-Fuzz agent skills: installation, usage and verification guide

An end-to-end walkthrough: install the skills into your agent, run the coverage pipeline on OSS-Fuzz projects, and verify the results at every stage, from a single local run all the way up to production coverage numbers.

Companion to [README.md](README.md), which covers the folder overview and the threat model.

## 1. What you have

| Piece | Role |
|---|---|
| Six knowledge skills | `oss-fuzz-engineer` (infrastructure) plus one fuzzing skill per language: `fuzzing-memory-unsafe-expert`, `fuzzing-go-expert`, `fuzzing-rust-expert`, `fuzzing-jvm-expert`, `fuzzing-python-expert` |
| `oss-fuzz-coverage-pipeline` | The orchestrator skill: project selection with upstream viability checks, build fixes, live coverage triage, harness/corpus/dictionary improvements, and delivery as worktree branch duo pairs validated through a temporary copy bridge. It auto-detects each project's language from `project.yaml` and activates the matching language skill. |
| `fuzzing-coverage-targeting` | The architect skill: which fuzz targets are worth creating and what shape each harness takes (worth model, taxonomy, patterns, portfolio and overlap rules); used by the pipeline in Phases 2, 3 and 5, and usable on its own |
| `oss-fuzz-coverage-pipeline/scripts/select_projects.sh` | Deterministic project selector: globs, `--language`, `--broken`, `--limit`, `--exclude`. |
| `copy_to_global.sh` | Installer: `claude` (the default), `gemini`, or any skills directory you name. |
| `helper.py` | An optional headless batch driver for the `claude` and `gemini` CLIs only; it is not needed for interactive use. |

The skills are plain `SKILL.md` markdown, so they are model-agnostic and portable to any skill-compatible host (Claude Code, Gemini CLI, or Cline in VS Code) with any model, including GLM via Z AI.

### 1.1 The seventh skill is a wrapper around the other six

`oss-fuzz-coverage-pipeline` is not a replacement for the six knowledge skills; it is an orchestrator that composes them. For every project it activates two companions: `oss-fuzz-engineer` (always, for infrastructure knowledge) plus exactly one language skill, picked automatically from the project's `project.yaml` `language` field:

| `project.yaml` language | Sub-skill the wrapper activates |
|---|---|
| `c`, `c++`, or missing | `fuzzing-memory-unsafe-expert` |
| `go` | `fuzzing-go-expert` |
| `rust` | `fuzzing-rust-expert` |
| `jvm` | `fuzzing-jvm-expert` |
| `python` | `fuzzing-python-expert` |
| other (javascript, swift, ruby, ...) | none dedicated: `oss-fuzz-engineer` only, or scope the run with `--language` |

The wrapper delegates all domain knowledge to those skills and their references: how to write harnesses in each language, how to drive `infra/helper.py`, how to read coverage reports and how to generate structured seeds. What the wrapper itself contributes is the process layer that none of the six contain: project selection and upstream viability checks, the phase discipline, the git guardrails, worktree duo pairs with the temporary copy bridge, the validation gates with the fix budget, the run manifest, rejection handling and the final summary.

The six knowledge skills remain fully usable on their own; the wrapper simply composes them into one end-to-end delivery pipeline, so nothing in them was duplicated or superseded. The architect skill `fuzzing-coverage-targeting` joins the composition in Phases 2, 3 and 5 to rank worthy targets and shape harnesses (default cap 5 pairs per project, adjustable in your prompt); the wrapper remains the only boss.

## 2. Prerequisites

- A skill-compatible agent host: **Cline** (VS Code), **Claude Code** or **Gemini CLI**. Any model works; nothing here is model-specific.
- **Docker**, because the pipeline builds projects through OSS-Fuzz's `infra/helper.py`.
- **Python 3** and **curl** (the selector's `--broken` mode fetches the public build status).
- This oss-fuzz checkout on disk.
- **Security**: this tooling builds and runs untrusted open-source code. Run it in a sandbox or VM on a trusted network (see the threat model in README.md).

## 3. Installation

Run from `infra/experimental/agent-skills/` inside your oss-fuzz checkout:

```sh
cd <oss-fuzz-checkout>/infra/experimental/agent-skills

./copy_to_global.sh                # Claude Code, installs to ~/.claude/skills (the default)
./copy_to_global.sh gemini         # Gemini CLI, installs to ~/.gemini/skills
./copy_to_global.sh /path/to/vscode-workspace/.cline/skills   # Cline (any model)
./copy_to_global.sh /any/skills/dir    # any other SKILL.md-compatible agent
./copy_to_global.sh claude gemini DIR  # several targets at once
```

Notes:

- All seven skills are installed **as a set**, because they cross-reference each other.
- Existing skills of the same name in the target directory are **overwritten**.
- The installed copy is a **copy**, so after editing any skill here, re-run the installer to refresh it.

## 4. Verify the installation

Check per host, after starting a **fresh session** (skills are scanned at startup):

- **Claude Code**: ask *"what skills do you have?"* and expect seven, including `oss-fuzz-coverage-pipeline`; typing `/` should offer `/oss-fuzz-coverage-pipeline`.
- **Gemini CLI**: `/skills list` (or `/skills reload` after reinstalling).
- **Cline**: bottom bar, scale icon, **Skills tab**: seven skills listed; typing `/` in chat offers the skill commands.

Then smoke-test the selector (it works from any directory):

```sh
<oss-fuzz-checkout>/infra/experimental/agent-skills/oss-fuzz-coverage-pipeline/scripts/select_projects.sh 'json*'
```

Expected output: project names with auto-detected languages, for example:

```
json		c++
json-c		c++
jsonparser	go
jsonpickle	python
json5format	rust
...
Selected 18 project(s) matching: json*
```

## 5. Usage

There are two ways to run the pipeline. Both use the same installed skills, follow the same phases and produce the same deliverables; they differ only in who drives the agent.

### 5.1 Two ways to run

| | Approach A: interactive | Approach B: helper.py batch |
|---|---|---|
| Hosts | any skill-compatible host (Cline, Claude Code, Gemini CLI), any model | the `claude` or `gemini` CLI only |
| Style | conversational, you approve each step | headless, one prompt per project |
| Parallelism | one project at a time | parallel sessions, default 2, `-j` to change |
| Best for | pilots, first runs, learning the flow, tight review | batches of projects and repeated campaigns |

### 5.2 Select the project set (shared by both approaches)

```sh
SEL=<oss-fuzz-checkout>/infra/experimental/agent-skills/oss-fuzz-coverage-pipeline/scripts

$SEL/select_projects.sh '*'                      # all 1,382 projects (any language)
$SEL/select_projects.sh --language c,c++ '*'     # the ~600 C/C++ projects
$SEL/select_projects.sh 'lib*' 'json*'           # glob subset
$SEL/select_projects.sh --broken --limit 20 '*'  # currently broken builds first
$SEL/select_projects.sh --exclude 'curl,wget' --language c,c++ '*'
```

The recommended order at scale is **broken builds first** (quick wins that also unlock coverage data), followed by the lowest own-code coverage on security-sensitive surface.

### 5.3 Approach A: run interactively (any host or model)

Single project: either phrase it naturally and let the description auto-trigger the skill:

> Use the oss-fuzz-coverage-pipeline skill on json-c: verify upstream viability from the Dockerfile, fix its builds, triage its live coverage on its own code, improve fuzz targets, corpora and dictionaries where security-sensitive, and deliver a worktree branch duo pair. Never commit, never push and do not stage by default.

or force the skill explicitly with `/oss-fuzz-coverage-pipeline`.

Multiple projects:

> Use the oss-fuzz-coverage-pipeline skill. Phase 0: run scripts/select_projects.sh --broken --limit 5 'lib*', verify upstream viability for each, record the manifest, then run the full pipeline on each viable project, one at a time, resuming from the manifest between sessions.

### 5.4 What the agent will do in either approach (Phases 0 to 5)

0. Select the projects with the selector, then verify upstream viability by reading the **Dockerfile** (never trusting `main_repo`): archived, inactive for 24 months or more, moved, or not a git repository all mean stop and notify `blocked(...)`. The selector reports the language **declared** in project.yaml; the Dockerfile base image is never a language signal. All project data is reread fresh on every run, so a project whose project.yaml changed since an earlier run is treated according to the new values, never previous memory. Reruns after a previous batch of duo pairs likewise re-derive coverage and targets from fresh data, because the previous batch may have changed the picture. Record a run manifest at `build/coverage-pipeline/manifest.md`.
1. Fix builds through `infra/helper.py` only: the main fuzzer build fix is always mandatory; coverage and introspector build fixes are optional only when the failure cause is missing corpora or an OOM/timeout, with the exemption recorded.
2. Triage live coverage using the canonical report URLs (overall `reports/<YYYYMMDD>/linux/report.html` and per target `reports-by-target/<YYYYMMDD>/<fuzzer>/linux/report.html`), walking the date back up to 30 days when coverage builds failed, plus the Introspector project profile. It verifies build scope before trusting percentages, treats statically-reached-but-dynamically-unreached functions as prime targets, and filters to security-sensitive attack surface. It also verifies the declared language against reality and switches the language sub-skill if project.yaml is mislabelled, continuing in all cases and recording the discrepancy; a per-pair override applies for mixed-language projects. Target selection and harness shaping come from the architect skill `fuzzing-coverage-targeting`, producing a ranked multi-target portfolio with overlap-aware incremental worth (default cap 5 pairs per project, adjustable in your prompt).
3. Act: new or updated harnesses, structured seed corpora, dictionaries, enabling missing modules and build-configuration fixes, via the language-appropriate skill. It never modifies upstream product code: upstream changes are limited to fuzzers with their corpora, dictionaries and options, fuzz build configuration and `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`-guarded additions; product-code bugs become findings.
4. Stage a **worktree branch duo pair** (OSS-Fuzz side `oss-fuzz-<project>-<suffix>`, upstream side `<project>-<suffix>`, always both, even with no OSS-Fuzz changes), created from pristine default-branch clones inside one marked working area, with a tagged **temporary copy bridge** in the Dockerfile simulating the merged upstream. Changes stay as plain working-tree files: no staging by default, never a commit, never a push. A project may yield several pairs when worthwhile: fuzzer pairs, each carrying its harness plus that harness's corpora, dictionaries and options; one consolidated standalone corpus/dict/options pair (`-corpus-dict-options`); and, when the main build was broken, a `-build-fix` pair created first, whose changes later pairs copy in purely as a testing scaffold and remove again after conclusion.
5. Validate each pair through `infra/helper.py`: the full sanitizer and engine matrix declared in `project.yaml`; `check_build` per new or updated fuzzer (mandatory, or failing solely due to a marked real finding); a fuzzing-quality gate (120 seconds minimum, 300 for corpus-heavy changes, nothing fuzzer-attributable within the first 60 seconds, no stale coverage in the final half); and a coverage gain read from the runs' libFuzzer `cov:` metric (fast path; a coverage build only as fallback). Every post-build crash, leak, OOM, timeout or assertion is classified first: real upstream findings keep the pair delivered with the discovery marked, while only fuzzer faults consume the fix budget of 3 rounds, after which the pair is moved to the rejected area, never deleted. Nothing is ever newly silenced, pre-existing suppressions are honoured unchanged, and a timeout from genuinely heavy legitimate processing may receive a measured, light increase delivered as fuzzer options.

Crashes, leaks, OOMs, timeouts and assertions are classified (fuzzer fault versus real finding); real findings are **documented with reproducers**, never hidden and never silenced.

### 5.5 The deliverables (either approach)

- The list of surviving worktree branch duo pairs (possibly several per project, grouped by the Phase 4 rules: fuzzer pairs with their own corpora, dictionaries and options, one standalone corpus pair, and a build-fix pair when needed), with paths and base commit SHAs recorded.
- `summary.md` in the marked working area: one markdown table row per duo pair (project, language, duo branches, worktree paths, summary of work, coverage delta, status).
- Skipped or unprocessable projects in the same table with the concrete reason.
- Rejected duo pairs moved into the rejected area and marked clearly, with the failure reason and what was attempted.
- Per-project reports, the manifest, and the next actions for you.

### 5.6 Approach B: run the same work with helper.py (headless, Claude Code and Gemini CLI)

`helper.py` drives the same skills without an interactive session: it builds task-specific prompts that reference the skills (including `oss-fuzz-coverage-pipeline` and `fuzzing-coverage-targeting`), auto-detects `claude` or `gemini` on `PATH`, and launches one headless session per project, in parallel (default 2). The skills must be installed for the CLI it drives (`~/.claude/skills` or `~/.gemini/skills`; see section 3).

Equivalent commands for the manual steps:

| Manual step (Approach A) | helper.py equivalent |
|---|---|
| Preview what will be asked | `python3 infra/experimental/agent-skills/helper.py show-prompt <command> <projects...>` |
| Full pipeline on named projects | `python3 infra/experimental/agent-skills/helper.py coverage-pipeline proj1 proj2` (the prompt is generated automatically; `--cap N` overrides the pair cap) |
| Discover broken projects and run the full pipeline | `python3 infra/experimental/agent-skills/helper.py coverage-pipeline --broken --limit 10` |
| Fix known-broken builds | `python3 infra/experimental/agent-skills/helper.py fix-builds proj1 proj2` |
| Discover and fix broken builds | `python3 infra/experimental/agent-skills/helper.py fix-broken-builds --language c,c++ --limit 20 -j 2` (add `--print-only` to preview the selection) |
| Expand coverage on a project | `python3 infra/experimental/agent-skills/helper.py expand-oss-fuzz-projects proj` |
| Onboard a new project | `python3 infra/experimental/agent-skills/helper.py integrate-project https://github.com/org/repo` |
| Clean local run artefacts | `python3 infra/experimental/agent-skills/helper.py clean proj` |

A typical batch run:

```sh
cd <oss-fuzz-checkout>
# 1. Dry run: print the exact prompt that would be sent.
python3 infra/experimental/agent-skills/helper.py show-prompt --task coverage-pipeline htslib
# 2. Run it across the batch.
python3 infra/experimental/agent-skills/helper.py coverage-pipeline --cap 5 htslib json-c
# 3. Watch progress; each session logs here.
tail -f build/agent-logs/*.log
```

Session output lands in `build/agent-logs/<project>-<timestamp>.log`, and each agent writes a per-project report under `projects/<project>/`; verification afterwards is exactly section 6.

Caveats: helper.py only drives the `claude` and `gemini` CLIs (Cline users stay with Approach A); sessions run with permissions skipped, so respect the threat model in README.md and use a sandbox; `fix-builds` and `expand-oss-fuzz-projects` use their own built-in workflows, which are narrower than the full pipeline (`coverage-pipeline` is the full-protocol command, and `run-task` remains for free-form work); and parallelism is bounded by Docker capacity, so keep `-j 2` unless your machine can take more concurrent builds.

## 6. Verify the results

### 6.1 Immediately: what to inspect after each project

| Artifact | Where | What "good" looks like |
|---|---|---|
| Run manifest | `build/coverage-pipeline/manifest.md` (oss-fuzz root) | A row per project with language, status, duo branches, worktree paths, base SHAs and report link |
| Final summary | `<working-area>/summary.md` | One table covering every selected project and every pair: delivered, rejected (moved to rejected area) and skipped, each with its reason where relevant, and a depends-on column recording pairs tested with a copied build fix |
| Duo pairs | `<working-area>/worktrees/oss-fuzz/` and `worktrees/upstream/` | Both branches exist (`oss-fuzz-<project>-<suffix>` and `<project>-<suffix>`), each holding plain working-tree changes |
| Git safety | both worktrees | Nothing staged (unless justified and recorded), nothing committed, nothing pushed, anywhere |
| Bridge | OSS-Fuzz worktree Dockerfile | Tagged `OSS-FUZZ-AGENT-BRIDGE:BEGIN/END` blocks plus the marked staging folder, kept intact for your manual removal later |
| Validation evidence | per-project report | The declared sanitizer/engine matrix built; per-fuzzer `check_build` passes (or fails solely due to a marked real finding); quality-gate run logs (120 s minimum, nothing fuzzer-attributable, no staleness); fast-path `cov:` deltas (coverage build only as fallback) |

Handy checks:

```sh
# Working-tree changes present, nothing staged, in both worktrees:
git -C <oss-fuzz-worktree>   status --short
git -C <upstream-worktree>   status --short

# Nothing accidentally committed on the branches:
git -C <oss-fuzz-worktree>   log --oneline main..HEAD        # expect nothing

# Rejected pairs moved, not deleted:
ls <working-area>/rejected/
```

### 6.2 Definition of done (per project, taken from the skill)

- [ ] All mandatory builds green from the OSS-Fuzz worktree; per-fuzzer `check_build` passes (or fails solely due to a marked real finding)
- [ ] Quality gate clean for every new or changed target: 120 s minimum, nothing fuzzer-attributable, no staleness; real findings excepted and marked
- [ ] Coverage: documented gains on the targeted files and zero digression elsewhere
- [ ] Duo pair holds plain working-tree changes; nothing staged, committed or pushed
- [ ] Bridge tagged and kept; rejection (if any) moved to the rejected area; manifest row final

### 6.3 Your review and merge loop (the human part)

1. Read the summary table and the per-project reports; spot-check the diffs in both worktrees of each delivered pair.
2. Commit the **upstream branch first**, then the OSS-Fuzz branch (the bridge assumes the upstream content), and push both.
3. After the real upstream merge, remove the bridge blocks and the bridge staging folders manually (this is why they are tagged).
4. File crash **findings** as upstream issues; the reproducers are in the reports.
5. Move or remove the delivered worktrees as you see fit, revisit or discard the rejected pairs, and remove the pristine clones once the base SHAs are no longer needed.
6. Mark the manifest rows `delivered` (or leave the recorded rejected/skipped states).

### 6.4 After merging: verify in production

After your changes land and OSS-Fuzz production rebuilds (usually within a day):

- **Build status** green for the project: `https://oss-fuzz-build-logs.storage.googleapis.com/status.json`
- **Coverage actually improved**: the canonical latest-report pointer is `https://storage.googleapis.com/oss-fuzz-coverage/latest_report_info/<project>.json`; open its `summary.json` and compare own-code covered lines against the baseline recorded in your report. Per-target views live under `reports-by-target/<YYYYMMDD>/<fuzzer_binary_name>/linux/report.html`.
- **Reachability improved** (optional): the project profile at `https://introspector.oss-fuzz.com/project-profile?project=<project>` should show fewer reachable-but-dark functions.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| Skill does not auto-trigger | Invoke it explicitly: `/oss-fuzz-coverage-pipeline`, or "use the ... skill" |
| Skill not listed after install | Start a fresh session; on Gemini run `/skills reload`; confirm the install path is the one your host reads |
| Agent uses old skill behaviour | The installed copy is stale; re-run `copy_to_global.sh` |
| Project skipped as blocked(...) | That is by design: archived, inactive (24 months), moved and non-git upstreams always stop and notify; the reason is in the summary and manifest |
| Pair keeps failing the gates | The fix budget is 3 rounds; afterwards the pair is rejected and moved to the rejected area, ready for a later attempt |
| Fuzzer crashes but it looks like a genuine bug | Classify first: real findings keep the pair delivered and marked; only fuzzer faults use the fix budget; never silence leaks, OOMs or timeouts |
| Agent wants to patch upstream product code | Forbidden: upstream changes are limited to fuzzers, fuzz build configuration and macro-guarded additions; product-code bugs are findings |
| Dependent pair retains some build-fix content | Entangled same-line edits; the residual fragment is flagged in the report and summary, and is safe because the fix branch commits first |
| Selector `--broken` fails | It needs network access and curl; check that `status.json` is reachable |
| Concurrent builds clobber Docker images | Pipeline rule: one project (per project name) at a time |
| Agent tries to commit, push or stage | Interrupt it; the skill forbids all three (staging only when absolutely necessary); review the branch |
| Coverage looks worse locally | Like-for-like rule: never compare fresh local runs with production reports (see the skill references) |
