#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Wrapper script for launching agent sessions on OSS-Fuzz projects.

Usage:
  python infra/experimental/agent-skills/helper.py expand-oss-fuzz-projects \
      open62541 json-c htslib

  python infra/experimental/agent-skills/helper.py fix-builds \
      open62541 json-c htslib

  python infra/experimental/agent-skills/helper.py run-task \
      --task "Investigate why the XML parser harness has low branch coverage \
              and add targeted harnesses for the attribute-parsing paths." \
      open62541 json-c

  python infra/experimental/agent-skills/helper.py add-chronos-support \
      open62541 json-c htslib

This will launch parallel agent sessions to expand fuzzing coverage, fix
broken builds, add Chronos support, or carry out an arbitrary task for each
listed project, producing local changes and a per-project report.
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta

DEFAULT_MAX_PARALLEL = 2

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OSS_FUZZ_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..'))

# Agent CLIs we know how to drive, in order of preference.
SUPPORTED_AGENTS = ['claude', 'gemini']

FUZZING_SKILLS_BLURB = (
    '- **oss-fuzz-engineer** – for all OSS-Fuzz infrastructure interaction\n'
    '      (building, running, checking fuzz targets, generating coverage reports).\n'
    '    - Pick the **language-appropriate fuzzing skill** based on the project\'s\n'
    '      primary language:\n'
    '      - C/C++   → **fuzzing-memory-unsafe-expert**\n'
    '      - Go      → **fuzzing-go-expert**\n'
    '      - Rust    → **fuzzing-rust-expert**\n'
    '      - Java/Kotlin/JVM → **fuzzing-jvm-expert**\n'
    '      - Python  → **fuzzing-python-expert**\n'
    '    Activate all relevant skills at the start of your session.')

EXPAND_SIZE_GUIDANCE = {
    'small':
        'Focus on a **single, well-justified improvement** — one new harness '
        'or a meaningful improvement to an existing one.',
    'medium':
        'Aim for **2–3 focused improvements** — new harnesses or meaningful '
        'extensions of existing ones.',
    'large':
        'Be **comprehensive** — target 5 or more distinct under-covered areas '
        'with new harnesses or major extensions to existing ones.',
}

EXPAND_ROUND_CONTEXT_TEMPLATE = textwrap.dedent("""\
    ## Continuation: Round {round_num} of {total_rounds}

    A previous expansion round has already run for this project. Before doing
    anything else, read and extract the following artifacts from the previous
    round's report at `{previous_report_path}`.  Each artifact directly shapes
    what you should do in this round.

    ### Artifacts to extract from `{previous_report_path}`

    1. **Harnesses added** — read the "Harnesses added this round" section.
       List every harness filename that was written. Do NOT re-implement any
       of these.  If build.sh was updated, re-read it now to see the current
       state before making further changes.

    2. **Coverage delta** — read the "Coverage delta" section. Note the
       overall line/branch coverage percentages before and after round
       {prev_round_num}.  Use the *after* numbers as your new baseline: any
       improvement you measure this round must be on top of that baseline.
       The previous round's coverage output directory is at:
       `{prev_cov_after_dir}`
       Read `{prev_cov_after_dir}/linux/summary.json` (if it exists) to get
       per-file hit/total line counts — use this to find files that are still
       poorly covered.

    3. **Candidate functions not yet targeted** — read the "Remaining coverage
       gaps" section. The previous round identified under-covered functions
       but may not have targeted all of them. Pick from that list first before
       doing fresh analysis, prioritising functions with the lowest hit ratio
       that sit on a security-relevant code path.

    4. **Threat model notes** — read the "Threat model" section. The previous
       round reasoned about which input paths reach security-sensitive code.
       Do not repeat that reasoning from scratch; extend it. If the previous
       round found that a certain subsystem (e.g. the XML parser) was already
       well-targeted, skip it and focus on the next highest-risk subsystem
       identified there.

    5. **Iteration failures** — read the "Approaches tried and abandoned"
       section (if present). Any harness design that was attempted but
       discarded (e.g. caused false positives, had zero coverage gain, was
       too slow) must NOT be retried. Note the reasons and use them to avoid
       the same dead ends.

    ### What to do differently this round

    - Start from the state left by round {prev_round_num}: the repo already
      has the harnesses, Dockerfile changes, and build.sh edits from that
      round. Do not undo or re-apply them.
    - Target the coverage gaps and candidate functions surfaced above.
    - If coverage stalled completely in the previous round despite multiple
      attempts, change subsystem — pick the next-highest-risk area from the
      threat model notes rather than hammering the same code paths.
    - Your coverage baseline for this round is the *after* state of round
      {prev_round_num}.  Measure improvement relative to that, not relative
      to the original project state.

""")

EXPAND_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with expanding the fuzzing coverage of
    the **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them for every step below.
{round_context}
    ## Objective

    Expand the fuzzing posture of the **{project}** project by adding one or
    more new fuzzing harnesses (or meaningfully improving existing ones) so that
    code coverage increases. {expansion_size_guidance}

    ## Step-by-step workflow

    1. **Understand the current state**
       - Read the project files in `projects/{project}/` (Dockerfile, build.sh,
         project.yaml, and any existing harnesses).
       - Fetch the latest public code coverage report for the project. Coverage
         reports are at:
         `https://storage.googleapis.com/oss-fuzz-coverage/{project}/reports/YYYYMMDD/linux/summary.json`
         Try recent dates (last few days) until you find one.
       - Identify under-covered source files and functions that sit on the
         attack surface (parsers, network handlers, file I/O, APIs exposed to
         untrusted input).

    2. **Clone the target source locally**
       - Study the Dockerfile to find the upstream repository URL.
       - Clone it locally under the OSS-Fuzz tree (e.g. into a directory next
         to the project folder) and adjust the Dockerfile to use `COPY` instead
         of `git clone` so you can iterate quickly.

    3. **Design and write new harness(es)**
       - Pick the most impactful under-covered area and write a new
         libFuzzer-style harness targeting it.
       - Follow the best practices from the *fuzzing-memory-unsafe-expert*
         skill: simplicity, determinism, enough entropy, matching the threat
         model, no false positives.
       - Update `build.sh` to compile and install the new harness.
       - Add a dictionary or seed corpus if relevant.

    4. **Build and validate**
       ```
       python3 infra/helper.py build_fuzzers {project}
       python3 infra/helper.py check_build {project}
       ```
       Fix any build errors until both commands succeed.

    5. **Run the new fuzzer briefly**
       ```
       python3 infra/helper.py run_fuzzer {project} <new_fuzzer_name> -- -max_total_time=30
       ```
       Confirm it does not crash immediately (instant crash = likely bug in the
       harness).

    6. **Measure coverage impact**
       Use round-stamped output directories so later rounds can locate this
       round's coverage data precisely.

       Generate a *before* baseline (using the build as it stands at the start
       of this round, before your new harnesses are added):
       ```
       python3 infra/helper.py introspector --coverage-only --seconds 30 \\
           --out {project}-cov-before{round_label} {project}
       ```

       After your changes:
       ```
       python3 infra/helper.py introspector --coverage-only --seconds 30 \\
           --out {project}-cov-after{round_label} {project}
       ```

       Compare the two `linux/summary.json` files and confirm that overall
       coverage did not regress. If you see no coverage improvement, go back
       to steps 3–6 and try a different approach. Keep iterating until you
       have a clear improvement.

    7. **Write a report**
       Create a file `{report_path}` with the following sections. Sections
       marked *(hand-off)* are consumed verbatim by the next round's agent —
       write them carefully and completely.

       - **Summary of changes**: list every file modified and what changed.

       - **Harnesses added this round** *(hand-off)*: one line per harness —
         filename, entry-point function fuzzed, and one sentence on why that
         target was chosen. Future rounds use this list to avoid duplication.

       - **Threat model** *(hand-off)*: which subsystems / input paths were
         analysed, which are security-relevant, which have already been
         covered (by this and prior rounds), and which remain untargeted.
         Be specific: name source files and functions.

       - **Coverage delta** *(hand-off)*: the overall line and branch
         coverage percentages from `{project}-cov-before{round_label}` and
         `{project}-cov-after{round_label}` (read from `linux/summary.json`).
         Include the path to the *after* directory so the next round can
         load it as its baseline.

       - **Remaining coverage gaps** *(hand-off)*: a ranked list of
         under-covered functions (name, file, hit/total line ratio) that were
         identified but NOT targeted this round, ordered by security
         relevance. The next round picks from this list first.

       - **Approaches tried and abandoned** *(hand-off)*: any harness designs
         that were attempted but discarded (e.g. zero coverage gain, false
         positives, excessive slowness), with a one-line reason for each.
         Future rounds must not retry these.

       - **Build / validation output**: excerpts from build_fuzzers,
         check_build, and run_fuzzer confirming success.

       - **Recommendations**: suggested next steps beyond the current set of
         rounds (seed corpora, dictionaries, sanitizer coverage, upstream
         notification).

    8. **Conclude**
       Do NOT commit or push anything. Leave all changes locally for the
       security engineer to review. End with a brief summary of what was done
       and where the report is.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{oss_fuzz_root}/projects/{project}`
    Write your report to: `{report_path}`

Once the work is done you should exit the process. Do NOT commit or push anything. Leave all changes locally for the security engineer to review.
""")

FIX_BUILD_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with fixing the broken build of the
    **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them for every step below.

    ## Objective

    Get the **{project}** OSS-Fuzz project back to a green build where both
    `build_fuzzers` and `check_build` pass without errors. The fix should be
    minimal and targeted — do not refactor or expand the project, just fix
    the breakage.

    ## Step-by-step workflow

    1. **Identify the failure**
       - Read the project files in `projects/{project}/` (Dockerfile, build.sh,
         project.yaml, and any existing harnesses).
       - Fetch the current build status from:
         `https://oss-fuzz-build-logs.storage.googleapis.com/status.json`
         Find the entry for **{project}** and note which configurations are
         failing (engine, sanitizer, architecture).
       - For each failing configuration, fetch the build log. Build log URLs
         follow the pattern:
         `https://oss-fuzz-build-logs.storage.googleapis.com/log-{project}.txt`
       - Carefully read the error messages to understand the root cause.

    2. **Reproduce the failure locally**
       ```
       python3 infra/helper.py build_fuzzers {project}
       ```
       If the build succeeds locally but fails on OSS-Fuzz, check whether the
       failure is specific to a sanitizer or engine:
       ```
       python3 infra/helper.py build_fuzzers --sanitizer address {project}
       python3 infra/helper.py build_fuzzers --sanitizer undefined {project}
       python3 infra/helper.py build_fuzzers --sanitizer memory {project}
       python3 infra/helper.py build_fuzzers --engine afl {project}
       ```

    3. **Diagnose the root cause**
       Common causes of build failures include:
       - Upstream API changes (renamed/removed functions, changed signatures).
       - New dependencies not installed in the Dockerfile.
       - Compiler flag incompatibilities with new compiler versions.
       - Harness bugs that cause `check_build` to fail (instant crashes).
       - Build system changes upstream (e.g. CMake option renames).

       If the issue is in the upstream source, clone it locally to investigate:
       - Study the Dockerfile to find the upstream repository URL.
       - Clone it locally and use `COPY` instead of `git clone` in the
         Dockerfile for faster iteration.

    4. **Apply the fix**
       - Make the minimal change needed to fix the build.
       - If the fix involves updating the Dockerfile, build.sh, or harness
         source, make those changes.
       - Do NOT add new features, new harnesses, or refactor existing code
         beyond what is needed for the fix.

    5. **Validate the fix**
       ```
       python3 infra/helper.py build_fuzzers {project}
       python3 infra/helper.py check_build {project}
       ```
       Both commands must succeed. If `check_build` fails, a harness is
       crashing immediately — investigate and fix that too.

       Run each fuzzer briefly to confirm it works:
       ```
       python3 infra/helper.py run_fuzzer {project} <fuzzer_name> -- -max_total_time=30
       ```

    6. **Validate other configurations if relevant**
       If the original failure was in a specific sanitizer or engine, also
       validate that configuration:
       ```
       python3 infra/helper.py build_fuzzers --sanitizer <failing_sanitizer> {project}
       python3 infra/helper.py check_build --sanitizer <failing_sanitizer> {project}
       ```

    7. **Write a report**
       Create a file `{report_path}` containing:
       - Root cause of the build failure.
       - Summary of the fix applied.
       - Build / check_build / run_fuzzer output excerpts showing success.
       - Any upstream issues that should be tracked or reported.

    8. **Conclude**
       Do NOT commit or push anything. Leave all changes locally for the
       security engineer to review. End with a brief summary of what was
       broken, what was fixed, and where the report is.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{oss_fuzz_root}/projects/{project}`
    Write your report to: `{report_path}`

Once the work is done you should exit the process. Do NOT commit or push anything. Leave all changes locally for the security engineer to review.
""")

FREE_TASK_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer working on the **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them throughout.

    ## Your task

    {task_description}

    ## Context

    - The project files are in `{oss_fuzz_root}/projects/{project}/`
      (Dockerfile, build.sh, project.yaml, and any existing harnesses).
    - Use `python3 infra/helper.py` for building, running, and checking fuzz
      targets. See the oss-fuzz-engineer skill for the full list of available
      commands.
    - You have full access to the filesystem and can clone upstream
      repositories, modify project files, and run builds locally.

    ## When you are done

    Write a report to `{report_path}` summarising:
    - What you did and why.
    - Any changes made to project files.
    - Build / validation output confirming your work.
    - Any follow-up recommendations.

    Do NOT commit or push anything. Leave all changes locally for the
    security engineer to review. End with a brief summary of what was done
    and where the report is.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{oss_fuzz_root}/projects/{project}`
    Write your report to: `{report_path}`

Once the work is done you should exit the process. Do NOT commit or push anything. Leave all changes locally for the security engineer to review.
""")

INTEGRATE_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with integrating a new open source
    project into OSS-Fuzz.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them for every step below.

    ## Project to integrate

    {project_url}

    ## Objective

    Create a complete, working OSS-Fuzz integration for the project at the URL
    above. The integration must pass `build_fuzzers` and `check_build` and
    include at least one meaningful libFuzzer harness that covers real attack
    surface.

    ## Step-by-step workflow

    1. **Assess the project**
       - Fetch the repository (README, source layout, build system) to
         understand what the project does, what language(s) it uses, and what
         its attack surface looks like (parsers, network handlers, file I/O,
         public APIs exposed to untrusted input).
       - Decide on a suitable OSS-Fuzz project name (conventionally the
         lower-case repository name, e.g. `my-lib`). This determines the
         directory you will create: `projects/<name>/`.
       - Verify that `projects/<name>/` does not already exist before
         proceeding.

    2. **Create the project skeleton**
       Create `projects/<name>/` containing:
       - **`project.yaml`** – fill in `homepage`, `language`, `main_repo`,
         `primary_contact` (use `oss-fuzz@google.com` if unknown),
         `fuzzing_engines` (at minimum `libfuzzer`), `sanitizers` (at minimum
         `address` and `undefined`), and set `base_os_version: ubuntu-24-04`.
       - **`Dockerfile`** – inherit from
         `gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04`, install build
         dependencies via `apt-get`, clone the upstream repository, and copy
         `build.sh` and any harness source files into the container.
       - **`build.sh`** – compile the project using `$CC`/`$CXX`,
         `$CFLAGS`/`$CXXFLAGS`, link harnesses against `$LIB_FUZZING_ENGINE`,
         and install binaries to `$OUT`. Include seed corpora or dictionaries
         in `$OUT` if relevant.

    3. **Clone the source locally**
       Clone the upstream repository into the OSS-Fuzz tree (alongside the
       project folder) and switch the Dockerfile to use `COPY` instead of
       `RUN git clone` so you can iterate quickly without network round-trips.

    4. **Study the attack surface and write harness(es)**
       - Identify the most security-relevant entry points: parsers, decoders,
         protocol handlers, file readers, APIs that accept untrusted bytes.
       - Write one focused libFuzzer harness (`LLVMFuzzerTestOneInput`) for
         the highest-impact entry point, following the best practices from the
         *fuzzing-memory-unsafe-expert* skill (simplicity, determinism, correct
         entropy, no false positives, matching the threat model).
       - Add the harness source to the project directory and update `build.sh`
         to compile it.
       - Add a dictionary or seed corpus if the target parses a structured
         format.

    5. **Build and validate**
       ```
       python3 infra/helper.py build_fuzzers <name>
       python3 infra/helper.py check_build <name>
       ```
       Iterate until both commands succeed without errors.

    6. **Run the harness briefly**
       ```
       python3 infra/helper.py run_fuzzer <name> <harness_name> -- -max_total_time=30
       ```
       Confirm it does not crash immediately (instant crash = harness bug,
       not a bug in the target). Fix and re-validate if it does.

    7. **Write a report**
       Create a file `{oss_fuzz_root}/projects/<name>/integration_report.md`
       containing:
       - Project description and rationale for integration (why is it a good
         OSS-Fuzz candidate?).
       - Overview of the attack surface and which entry points are covered.
       - Description of each harness: what it targets and why.
       - Build / check_build / run_fuzzer output excerpts confirming success.
       - Suggested next steps: additional harnesses, seed corpora, sanitizer
         coverage, upstream notification.

    8. **Conclude**
       Do NOT commit or push anything. Leave all files locally for the
       security engineer to review. End with a brief summary of the project
       name chosen, what was created, and where the report is.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    Create the project directory at: `{oss_fuzz_root}/projects/<name>/`
    Write your report to: `{oss_fuzz_root}/projects/<name>/integration_report.md`

Once the work is done you should exit the process. Do NOT commit or push anything. Leave all changes locally for the security engineer to review.
""")

ADD_CHRONOS_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with adding Chronos support to the
    **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them for every step below.

    ## What is Chronos

    Chronos is a feature of OSS-Fuzz that enables fast, offline rebuilds and
    unit-test runs for a project — without network access. It is used to
    validate patches quickly without rebuilding the entire Docker image from
    scratch. Two scripts must be added to the project directory:

    - **`replay_build.sh`**: rebuilds the project (and its fuzz targets)
      entirely offline, using only files already present in the container.
    - **`run_tests.sh`**: runs the project's own unit-test suite offline.
      Must leave the repository in exactly the same state as it found it
      (i.e. `git diff` is unchanged before and after).

    Read `infra/chronos/README.md` carefully before writing either script —
    it is the authoritative reference for constraints and conventions.

    ## Objective

    Add working `replay_build.sh` and `run_tests.sh` scripts to
    `projects/{project}/` so that both Chronos validation commands pass:

    ```
    python3 infra/helper.py check-replay {project}
    python3 infra/helper.py check-tests {project}
    ```

    ## Step-by-step workflow

    1. **Read the Chronos specification**
       - Read `infra/chronos/README.md` in full. Understand all constraints
         before touching any project files.

    2. **Understand the project**
       - Read `projects/{project}/` (Dockerfile, build.sh, project.yaml,
         and any existing harnesses).
       - Identify: the build system (CMake, Meson, Autotools, Make, …),
         the upstream repository URL, and the project's own test suite
         (CTest, pytest, gtest, …).

    3. **Clone the source locally**
       - Find the `git clone` line in the Dockerfile, clone the upstream
         repository locally alongside the project directory, and update the
         Dockerfile to use `COPY` so you can iterate without network
         round-trips.

    4. **Write `replay_build.sh`**
       - The script must rebuild the project and all fuzz targets using only
         files present in the container — no `apt-get`, no `git clone`, no
         network calls of any kind.
       - Mirror the essential compilation steps from `build.sh`, but omit
         any network-dependent setup.
       - Place the script at `projects/{project}/replay_build.sh`.

    5. **Write `run_tests.sh`**
       - The script must run the project's unit tests with no network access.
       - Any test that requires network connectivity must be explicitly
         skipped; document each such skip with a comment explaining why.
       - After the script exits, `git diff` inside the target repository must
         be identical to what it was before the script ran. Clean up any
         build artefacts or temporary files the test suite creates.
       - If the tests fail, the script must exit with a non-zero status so
         that `check-tests` correctly reports failure.
       - Place the script at `projects/{project}/run_tests.sh`.

    6. **Validate**
       Run both Chronos checks and iterate until both pass without error:
       ```
       python3 infra/helper.py check-replay {project}
       python3 infra/helper.py check-tests {project}
       ```
       Also confirm the normal OSS-Fuzz build still passes:
       ```
       python3 infra/helper.py build_fuzzers {project}
       python3 infra/helper.py check_build {project}
       ```

    7. **Write a report**
       Create a file `{report_path}` containing:
       - Overview of the build system and test suite found in the project.
       - Description of `replay_build.sh`: what it does and any simplifications
         made relative to `build.sh`.
       - Description of `run_tests.sh`: which tests are run, which are skipped
         (and why), and how idempotency is ensured.
       - Output of both `check-replay` and `check-tests` confirming success.
       - Any follow-up recommendations (e.g. tests that could be un-skipped
         once network access is available, or flaky tests to investigate).

    8. **Conclude**
       Do NOT commit or push anything. Leave all changes locally for the
       security engineer to review. End with a brief summary of what was
       created and where the report is.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{oss_fuzz_root}/projects/{project}`
    Write your report to: `{report_path}`

Once the work is done you should exit the process. Do NOT commit or push anything. Leave all changes locally for the security engineer to review.
""")

EXPAND_SUMMARY_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with writing a consolidated summary
    of a multi-round fuzzing expansion that was just completed for the
    **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    ## What happened

    A multi-round expansion ran {total_rounds} round(s) for this project.
    Each round added new fuzzing harnesses and measured coverage. Your job
    is to read every round's artifacts and synthesise them into a single,
    authoritative summary report.

    ## Artifacts to read

    For each round N from 1 to {total_rounds}, read:

    1. **Round report**: `{project_dir}/expansion_report_round_N.md`
       (contains the hand-off sections written by each round's agent)

    2. **Coverage baseline** (before that round's changes):
       `{oss_fuzz_root}/{project}-cov-before-roundN/linux/summary.json`

    3. **Coverage result** (after that round's changes):
       `{oss_fuzz_root}/{project}-cov-after-roundN/linux/summary.json`

    If a file is missing (e.g. a round was aborted), note that in the report
    and continue with what is available.

    Also read the current project files in `{project_dir}/` (Dockerfile,
    build.sh, and all harness source files) to confirm the final state of
    the project matches what the round reports describe.

    ## What to write

    Create a file at `{summary_path}` with the following sections:

    ### 1. Executive summary
    Two to four sentences: what project was expanded, how many rounds ran,
    how many harnesses were added, and the net coverage change from start
    to finish.

    ### 2. Harnesses added (complete list)
    A table with one row per harness added across all rounds:

    | Round | Harness file | Entry point fuzzed | Rationale |
    |---|---|---|---|

    ### 3. Coverage progression
    A table showing coverage at the start of each round and after it, plus
    the delta. Use the line-coverage percentage from each round's
    `summary.json`. Include a final row showing total gain from baseline
    (before round 1) to final state (after round {total_rounds}).

    | Round | Coverage before | Coverage after | Delta |
    |---|---|---|---|

    If per-file data is available, also list the top 5 source files with the
    largest absolute coverage gain across all rounds.

    ### 4. Threat model coverage
    Summarise which attack-surface areas were analysed across all rounds,
    which are now covered by at least one harness, and which remain
    unaddressed. Be specific: name subsystems, source files, and key
    functions.

    ### 5. Remaining coverage gaps
    A consolidated, de-duplicated, ranked list of under-covered functions
    and files that were identified but NOT targeted in any round. Order by
    security relevance (highest risk first). This section is the primary
    input for any future expansion work.

    ### 6. Approaches tried and abandoned
    A consolidated list of harness designs that were attempted across all
    rounds but discarded, with the reason for each. Future engineers must
    not retry these without first addressing the stated reason.

    ### 7. Recommendations
    Concrete next steps, ordered by impact:
    - Additional harnesses that should be written (name the function/file
      and explain why).
    - Seed corpora or dictionaries that would improve fuzzing efficiency.
    - Sanitizer or engine coverage gaps worth addressing.
    - Any upstream issues worth reporting to the project maintainers.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{project_dir}`
    Write the summary to: `{summary_path}`

Once the summary is written, exit. Do NOT commit or push anything.
""")

CONSOLIDATE_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer reviewing the fuzzing harnesses of the
    **{project}** OSS-Fuzz project after one or more expansion rounds.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    ## Objective

    One or more expansion rounds have just added new harnesses to this project.
    Take a look at the current harness set and decide whether any consolidation
    is warranted — for example removing or merging harnesses that are clearly
    redundant, or dropping ones that add little value. Use your own judgement
    on a case-by-case basis; not every project will need changes.

    Be conservative: when in doubt, keep a harness. Pre-existing harnesses
    (those already committed before this session) should only be touched if
    there is a clear reason.

    After any changes, confirm the project still builds and passes `check_build`.
    Write a short report to `{report_path}` summarising what you looked at,
    what you changed (if anything), and why.

    Do NOT commit or push anything. Leave all changes locally for the
    security engineer to review.

    ## Working directory

    You are working from: `{oss_fuzz_root}`
    The project directory is: `{project_dir}`
    Write your report to: `{report_path}`

Once consolidation is complete, exit.
""")


def get_recent_date_str(days_ago=1):
  """Return a YYYYMMDD string for a recent date."""
  dt = datetime.now() - timedelta(days=days_ago)
  return dt.strftime('%Y%m%d')


def find_agent_cli():
  """Find the first available agent CLI on PATH."""
  for agent in SUPPORTED_AGENTS:
    if subprocess.run(['which', agent], capture_output=True).returncode == 0:
      return agent
  return None


def _url_to_log_slug(url):
  """Convert a URL to a filesystem-safe slug for log file naming."""
  # Strip scheme (https://, http://) then replace slashes and dots with dashes.
  slug = url.split('://')[-1]
  for ch in '/\\:.':
    slug = slug.replace(ch, '-')
  return slug.strip('-')[:80]


def build_integrate_prompt(project_url):
  """Build the agent prompt for integrating a new project from a URL."""
  return INTEGRATE_PROMPT_TEMPLATE.format(
      project_url=project_url,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      fuzzing_skills_blurb=FUZZING_SKILLS_BLURB,
  )


def print_integrate_prompt(project_url):
  """Print the integration prompt that would be sent to an agent."""
  prompt = build_integrate_prompt(project_url)
  print(f'===== Integration prompt for {project_url} =====')
  print(prompt)
  print(f'===== End prompt for {project_url} =====\n')


def launch_integrate_session(agent_cli, project_url):
  """Launch an agent session to integrate a new project from a URL.

  Returns a subprocess.Popen object.
  """
  prompt = build_integrate_prompt(project_url)
  slug = _url_to_log_slug(project_url)

  print(f'[*] Launching {agent_cli} session to integrate: {project_url}')

  if agent_cli == 'claude':
    cmd = ['claude', '-p', prompt, '--dangerously-skip-permissions']
  elif agent_cli == 'gemini':
    cmd = ['gemini', '--yolo', '-p', prompt]
  else:
    print(f'[!] Unsupported agent CLI: {agent_cli}', file=sys.stderr)
    return None

  log_dir = os.path.join(OSS_FUZZ_ROOT, 'build', 'agent-logs')
  os.makedirs(log_dir, exist_ok=True)
  log_path = os.path.join(
      log_dir,
      f'integrate-{slug}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')

  log_file = open(log_path, 'w')
  print(f'    Log: {log_path}')

  proc = subprocess.Popen(
      cmd,
      cwd=OSS_FUZZ_ROOT,
      stdout=log_file,
      stderr=subprocess.STDOUT,
  )
  proc._log_file = log_file
  proc._log_path = log_path
  proc._project_url = project_url
  return proc


def _run_single_integrate_session(agent_cli, project_url):
  """Launch an integration session and wait for it to complete.

  Returns a dict with the URL, return code, and log path.
  """
  proc = launch_integrate_session(agent_cli, project_url)
  if proc is None:
    return {'url': project_url, 'returncode': -1, 'log_path': None}

  proc.wait()
  proc._log_file.close()
  status = 'OK' if proc.returncode == 0 else f'FAILED (rc={proc.returncode})'
  print(f'    [{status}] {proc._project_url}  (log: {proc._log_path})')
  return {
      'url': project_url,
      'returncode': proc.returncode,
      'log_path': proc._log_path,
  }


def _run_integrate_sessions(args):
  """Shared logic for launching parallel integration agent sessions."""
  urls = args.urls

  if args.print_only:
    for url in urls:
      print_integrate_prompt(url)
    return

  agent_cli = args.agent or find_agent_cli()
  if agent_cli is None:
    print(
        '[!] No supported agent CLI found on PATH '
        f'({", ".join(SUPPORTED_AGENTS)}).\n'
        '    Install one or use --print-only to see the prompts.',
        file=sys.stderr)
    sys.exit(1)

  max_parallel = args.max_parallel

  print(f'[*] Using agent CLI: {agent_cli}')
  print(f'[*] Task: integrate-project')
  print(f'[*] URLs: {", ".join(urls)}')
  print(f'[*] Max parallel sessions: {max_parallel}')
  print()

  print(f'[*] Launching {len(urls)} session(s) '
        f'(max {max_parallel} in parallel) ...\n')

  with concurrent.futures.ThreadPoolExecutor(
      max_workers=max_parallel) as executor:
    futures = {
        executor.submit(_run_single_integrate_session, agent_cli, url): url
        for url in urls
    }
    for future in concurrent.futures.as_completed(futures):
      future.result()

  print('\n[*] All sessions complete.')
  print('    Each agent writes its report to:')
  print(f'      {OSS_FUZZ_ROOT}/projects/<chosen-name>/integration_report.md')
  print('\n[*] Review local changes with:')
  print(f'    cd {OSS_FUZZ_ROOT} && git diff && git status')


def build_prompt(task,
                 project,
                 task_description=None,
                 round_num=1,
                 total_rounds=1,
                 expansion_size='medium'):
  """Build the agent prompt for a given task and project.

  Args:
    task: One of 'expand', 'fix-build', 'free-task', 'add-chronos'.
    project: OSS-Fuzz project name.
    task_description: Free-form task description (free-task only).
    round_num: Current expansion round (1-based; expand only).
    total_rounds: Total number of rounds planned (expand only).
    expansion_size: 'small', 'medium', or 'large' (expand only).
  """
  if task == 'expand':
    if total_rounds > 1:
      report_name = f'expansion_report_round_{round_num}.md'
    else:
      report_name = 'expansion_report.md'
    template = EXPAND_PROMPT_TEMPLATE
  elif task == 'fix-build':
    report_name = 'fix_build_report.md'
    template = FIX_BUILD_PROMPT_TEMPLATE
  elif task == 'free-task':
    report_name = 'task_report.md'
    template = FREE_TASK_PROMPT_TEMPLATE
  elif task == 'add-chronos':
    report_name = 'chronos_report.md'
    template = ADD_CHRONOS_PROMPT_TEMPLATE
  else:
    raise ValueError(f'Unknown task: {task}')

  report_path = os.path.join(OSS_FUZZ_ROOT, 'projects', project, report_name)
  fmt_kwargs = dict(
      project=project,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      report_path=report_path,
      fuzzing_skills_blurb=FUZZING_SKILLS_BLURB,
  )
  if task == 'expand':
    fmt_kwargs['expansion_size_guidance'] = EXPAND_SIZE_GUIDANCE.get(
        expansion_size, EXPAND_SIZE_GUIDANCE['medium'])
    fmt_kwargs['round_label'] = (f'-round{round_num}'
                                 if total_rounds > 1 else '')
    if round_num > 1:
      prev_round_num = round_num - 1
      prev_report_name = (f'expansion_report_round_{prev_round_num}.md'
                          if total_rounds > 1 else 'expansion_report.md')
      previous_report_path = os.path.join(OSS_FUZZ_ROOT, 'projects', project,
                                          prev_report_name)
      prev_cov_after_dir = os.path.join(
          OSS_FUZZ_ROOT, f'{project}-cov-after-round{prev_round_num}')
      fmt_kwargs['round_context'] = '\n' + EXPAND_ROUND_CONTEXT_TEMPLATE.format(
          round_num=round_num,
          total_rounds=total_rounds,
          prev_round_num=prev_round_num,
          previous_report_path=previous_report_path,
          prev_cov_after_dir=prev_cov_after_dir,
      )
    else:
      fmt_kwargs['round_context'] = ''
  if task_description is not None:
    fmt_kwargs['task_description'] = task_description
  return template.format(**fmt_kwargs), report_name


def print_prompt(task,
                 project,
                 task_description=None,
                 round_num=1,
                 total_rounds=1,
                 expansion_size='medium'):
  """Print the prompt that would be sent to an agent."""
  prompt, _ = build_prompt(task,
                           project,
                           task_description=task_description,
                           round_num=round_num,
                           total_rounds=total_rounds,
                           expansion_size=expansion_size)
  label = f'{task}'
  if task == 'expand' and total_rounds > 1:
    label += f' round {round_num}/{total_rounds}'
  print(f'===== Prompt for {project} ({label}) =====')
  print(prompt)
  print(f'===== End prompt for {project} =====\n')


def launch_agent_session(agent_cli,
                         task,
                         project,
                         task_description=None,
                         round_num=1,
                         total_rounds=1,
                         expansion_size='medium'):
  """Launch an agent session for a single project.

    Returns a subprocess.Popen object.
    """
  prompt, _ = build_prompt(task,
                           project,
                           task_description=task_description,
                           round_num=round_num,
                           total_rounds=total_rounds,
                           expansion_size=expansion_size)

  round_label = (f' round {round_num}/{total_rounds}'
                 if task == 'expand' and total_rounds > 1 else '')
  print(
      f'[*] Launching {agent_cli} session for project: {project} ({task}{round_label})'
  )

  if agent_cli == 'claude':
    cmd = ['claude', '-p', prompt, '--dangerously-skip-permissions']
  elif agent_cli == 'gemini':
    cmd = [
        'gemini',
        '--yolo',
        '-p',
        prompt,
    ]
  else:
    print(f'[!] Unsupported agent CLI: {agent_cli}', file=sys.stderr)
    return None

  log_dir = os.path.join(OSS_FUZZ_ROOT, 'build', 'agent-logs')
  os.makedirs(log_dir, exist_ok=True)
  round_suffix = (f'-round{round_num}'
                  if task == 'expand' and total_rounds > 1 else '')
  log_path = os.path.join(
      log_dir,
      f'{project}{round_suffix}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')

  log_file = open(log_path, 'w')
  print(f'    Log: {log_path}')

  proc = subprocess.Popen(
      cmd,
      cwd=OSS_FUZZ_ROOT,
      stdout=log_file,
      stderr=subprocess.STDOUT,
  )
  # Stash the log file handle so we can close it later.
  proc._log_file = log_file
  proc._log_path = log_path
  proc._project = project
  return proc


def build_consolidation_prompt(project):
  """Build the agent prompt for post-expansion harness consolidation."""
  project_dir = os.path.join(OSS_FUZZ_ROOT, 'projects', project)
  report_path = os.path.join(project_dir, 'harness_consolidation_report.md')
  return CONSOLIDATE_PROMPT_TEMPLATE.format(
      project=project,
      project_dir=project_dir,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      report_path=report_path,
      fuzzing_skills_blurb=FUZZING_SKILLS_BLURB,
  ), 'harness_consolidation_report.md'


def launch_consolidation_session(agent_cli, project):
  """Launch a consolidation agent session for a project.

  Returns a subprocess.Popen object.
  """
  prompt, _ = build_consolidation_prompt(project)

  print(
      f'[*] Launching {agent_cli} consolidation session for project: {project}')

  if agent_cli == 'claude':
    cmd = ['claude', '-p', prompt, '--dangerously-skip-permissions']
  elif agent_cli == 'gemini':
    cmd = ['gemini', '--yolo', '-p', prompt]
  else:
    print(f'[!] Unsupported agent CLI: {agent_cli}', file=sys.stderr)
    return None

  log_dir = os.path.join(OSS_FUZZ_ROOT, 'build', 'agent-logs')
  os.makedirs(log_dir, exist_ok=True)
  log_path = os.path.join(
      log_dir,
      f'{project}-consolidation-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')

  log_file = open(log_path, 'w')
  print(f'    Log: {log_path}')

  proc = subprocess.Popen(
      cmd,
      cwd=OSS_FUZZ_ROOT,
      stdout=log_file,
      stderr=subprocess.STDOUT,
  )
  proc._log_file = log_file
  proc._log_path = log_path
  proc._project = project
  return proc


def _run_single_consolidation_session(agent_cli, project):
  """Launch a consolidation session and wait for it to complete.

  Returns a dict with the project name, return code, and log path.
  """
  proc = launch_consolidation_session(agent_cli, project)
  if proc is None:
    return {'project': project, 'returncode': -1, 'log_path': None}

  proc.wait()
  proc._log_file.close()
  status = 'OK' if proc.returncode == 0 else f'FAILED (rc={proc.returncode})'
  print(
      f'    [{status}] {proc._project} consolidation  (log: {proc._log_path})')
  return {
      'project': project,
      'returncode': proc.returncode,
      'log_path': proc._log_path,
  }


def build_summary_prompt(project, total_rounds):
  """Build the agent prompt for the post-expansion summary."""
  project_dir = os.path.join(OSS_FUZZ_ROOT, 'projects', project)
  summary_path = os.path.join(project_dir, 'expansion_summary.md')
  return EXPAND_SUMMARY_PROMPT_TEMPLATE.format(
      project=project,
      total_rounds=total_rounds,
      project_dir=project_dir,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      summary_path=summary_path,
      fuzzing_skills_blurb=FUZZING_SKILLS_BLURB,
  ), 'expansion_summary.md'


def launch_summary_session(agent_cli, project, total_rounds):
  """Launch a summary agent session for a project after all rounds complete.

  Returns a subprocess.Popen object.
  """
  prompt, _ = build_summary_prompt(project, total_rounds)

  print(f'[*] Launching {agent_cli} summary session for project: {project}')

  if agent_cli == 'claude':
    cmd = ['claude', '-p', prompt, '--dangerously-skip-permissions']
  elif agent_cli == 'gemini':
    cmd = ['gemini', '--yolo', '-p', prompt]
  else:
    print(f'[!] Unsupported agent CLI: {agent_cli}', file=sys.stderr)
    return None

  log_dir = os.path.join(OSS_FUZZ_ROOT, 'build', 'agent-logs')
  os.makedirs(log_dir, exist_ok=True)
  log_path = os.path.join(
      log_dir,
      f'{project}-summary-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')

  log_file = open(log_path, 'w')
  print(f'    Log: {log_path}')

  proc = subprocess.Popen(
      cmd,
      cwd=OSS_FUZZ_ROOT,
      stdout=log_file,
      stderr=subprocess.STDOUT,
  )
  proc._log_file = log_file
  proc._log_path = log_path
  proc._project = project
  return proc


def _run_single_summary_session(agent_cli, project, total_rounds):
  """Launch a summary session and wait for it to complete.

  Returns a dict with the project name, return code, and log path.
  """
  proc = launch_summary_session(agent_cli, project, total_rounds)
  if proc is None:
    return {'project': project, 'returncode': -1, 'log_path': None}

  proc.wait()
  proc._log_file.close()
  status = 'OK' if proc.returncode == 0 else f'FAILED (rc={proc.returncode})'
  print(f'    [{status}] {proc._project} summary  (log: {proc._log_path})')
  return {
      'project': project,
      'returncode': proc.returncode,
      'log_path': proc._log_path,
  }


def _validate_projects(projects):
  """Validate that each project directory exists. Exits on failure."""
  missing = [
      p for p in projects
      if not os.path.isdir(os.path.join(OSS_FUZZ_ROOT, 'projects', p))
  ]
  if missing:
    print(
        f'[!] Unknown projects (no directory in projects/): '
        f'{", ".join(missing)}',
        file=sys.stderr)
    sys.exit(1)


def _run_single_session(agent_cli,
                        task,
                        project,
                        task_description=None,
                        round_num=1,
                        total_rounds=1,
                        expansion_size='medium'):
  """Launch an agent session and wait for it to complete.

  Returns a dict with the project name, return code, and log path.
  """
  proc = launch_agent_session(agent_cli,
                              task,
                              project,
                              task_description=task_description,
                              round_num=round_num,
                              total_rounds=total_rounds,
                              expansion_size=expansion_size)
  if proc is None:
    return {'project': project, 'returncode': -1, 'log_path': None}

  proc.wait()
  proc._log_file.close()
  status = 'OK' if proc.returncode == 0 else f'FAILED (rc={proc.returncode})'
  print(f'    [{status}] {proc._project}  (log: {proc._log_path})')
  return {
      'project': project,
      'returncode': proc.returncode,
      'log_path': proc._log_path,
  }


def _run_sessions(task, args):
  """Shared logic for launching parallel agent sessions."""
  projects = args.projects
  _validate_projects(projects)

  task_description = getattr(args, 'task_description', None)
  _, report_name = build_prompt(task, projects[0], task_description)

  if args.print_only:
    for project in projects:
      print_prompt(task, project, task_description)
    return

  agent_cli = args.agent or find_agent_cli()
  if agent_cli is None:
    print(
        '[!] No supported agent CLI found on PATH '
        f'({", ".join(SUPPORTED_AGENTS)}).\n'
        '    Install one or use --print-only to see the prompts.',
        file=sys.stderr)
    sys.exit(1)

  max_parallel = args.max_parallel

  print(f'[*] Using agent CLI: {agent_cli}')
  print(f'[*] Task: {task}')
  print(f'[*] Projects: {", ".join(projects)}')
  print(f'[*] Max parallel sessions: {max_parallel}')
  print()

  print(f'[*] Launching {len(projects)} session(s) '
        f'(max {max_parallel} in parallel) ...\n')

  results = []
  with concurrent.futures.ThreadPoolExecutor(
      max_workers=max_parallel) as executor:
    futures = {
        executor.submit(_run_single_session, agent_cli, task, project, task_description):
            project for project in projects
    }
    for future in concurrent.futures.as_completed(futures):
      results.append(future.result())

  # Summary.
  print('\n[*] All sessions complete. Check the following for results:')
  for project in projects:
    report = os.path.join(OSS_FUZZ_ROOT, 'projects', project, report_name)
    exists = 'EXISTS' if os.path.isfile(report) else 'MISSING'
    print(f'    - projects/{project}/{report_name}  [{exists}]')

  print('\n[*] Review local changes with:')
  print(f'    cd {OSS_FUZZ_ROOT} && git diff')


def _run_expand_sessions(args):
  """Handle expand-oss-fuzz-projects with multi-round and size support."""
  projects = args.projects
  _validate_projects(projects)

  rounds = args.rounds
  expansion_size = args.expansion_size
  total_rounds = rounds
  # Default: summary and consolidation on for multi-round, off for single round.
  run_summary = args.summary if args.summary is not None else (total_rounds > 1)
  run_consolidate = (args.consolidate if args.consolidate is not None else
                     (total_rounds > 1))

  if args.print_only:
    for project in projects:
      for round_num in range(1, total_rounds + 1):
        print_prompt('expand',
                     project,
                     round_num=round_num,
                     total_rounds=total_rounds,
                     expansion_size=expansion_size)
      if run_consolidate:
        prompt, _ = build_consolidation_prompt(project)
        print(f'===== Consolidation prompt for {project} =====')
        print(prompt)
        print(f'===== End consolidation prompt for {project} =====\n')
      if run_summary:
        prompt, _ = build_summary_prompt(project, total_rounds)
        print(f'===== Summary prompt for {project} =====')
        print(prompt)
        print(f'===== End summary prompt for {project} =====\n')
    return

  agent_cli = args.agent or find_agent_cli()
  if agent_cli is None:
    print(
        '[!] No supported agent CLI found on PATH '
        f'({", ".join(SUPPORTED_AGENTS)}).\n'
        '    Install one or use --print-only to see the prompts.',
        file=sys.stderr)
    sys.exit(1)

  max_parallel = args.max_parallel

  print(f'[*] Using agent CLI: {agent_cli}')
  print(f'[*] Task: expand')
  print(f'[*] Projects: {", ".join(projects)}')
  print(f'[*] Rounds per project: {total_rounds}')
  print(f'[*] Expansion size: {expansion_size}')
  print(f'[*] Consolidation agent: {"yes" if run_consolidate else "no"}')
  print(f'[*] Summary agent: {"yes" if run_summary else "no"}')
  print(f'[*] Max parallel sessions: {max_parallel}')
  print()

  def run_project_rounds(project):
    """Run all rounds then the summary agent sequentially for one project."""
    results = []
    completed_rounds = 0
    for round_num in range(1, total_rounds + 1):
      if total_rounds > 1:
        print(f'[*] {project}: starting round {round_num}/{total_rounds} ...')
      result = _run_single_session(agent_cli,
                                   'expand',
                                   project,
                                   round_num=round_num,
                                   total_rounds=total_rounds,
                                   expansion_size=expansion_size)
      results.append(result)
      if result['returncode'] != 0:
        print(f'    [!] {project}: round {round_num} failed '
              f'(rc={result["returncode"]}), stopping further rounds.')
        break
      completed_rounds += 1

    if run_consolidate and completed_rounds > 0:
      print(f'[*] {project}: running consolidation agent ...')
      consolidation_result = _run_single_consolidation_session(
          agent_cli, project)
      results.append(consolidation_result)

    if run_summary and completed_rounds > 0:
      print(f'[*] {project}: running summary agent over '
            f'{completed_rounds} completed round(s) ...')
      summary_result = _run_single_summary_session(agent_cli, project,
                                                   completed_rounds)
      results.append(summary_result)

    return results

  print(f'[*] Launching sessions for {len(projects)} project(s) '
        f'({total_rounds} round(s) each, max {max_parallel} projects in '
        f'parallel) ...\n')

  all_results = {}
  with concurrent.futures.ThreadPoolExecutor(
      max_workers=max_parallel) as executor:
    futures = {
        executor.submit(run_project_rounds, project): project
        for project in projects
    }
    for future in concurrent.futures.as_completed(futures):
      project = futures[future]
      all_results[project] = future.result()

  # Final report listing.
  print('\n[*] All sessions complete. Reports written:')
  for project in projects:
    for round_num in range(1, total_rounds + 1):
      _, report_name = build_prompt('expand',
                                    project,
                                    round_num=round_num,
                                    total_rounds=total_rounds,
                                    expansion_size=expansion_size)
      report = os.path.join(OSS_FUZZ_ROOT, 'projects', project, report_name)
      exists = 'EXISTS' if os.path.isfile(report) else 'MISSING'
      print(f'    - projects/{project}/{report_name}  [{exists}]')
    if run_consolidate:
      consolidation = os.path.join(OSS_FUZZ_ROOT, 'projects', project,
                                   'harness_consolidation_report.md')
      exists = 'EXISTS' if os.path.isfile(consolidation) else 'MISSING'
      print(
          f'    - projects/{project}/harness_consolidation_report.md  [{exists}]'
      )
    if run_summary:
      summary = os.path.join(OSS_FUZZ_ROOT, 'projects', project,
                             'expansion_summary.md')
      exists = 'EXISTS' if os.path.isfile(summary) else 'MISSING'
      print(f'    - projects/{project}/expansion_summary.md  [{exists}]')

  print('\n[*] Review local changes with:')
  print(f'    cd {OSS_FUZZ_ROOT} && git diff')


def cmd_expand(args):
  """Handle the expand-oss-fuzz-projects subcommand."""
  _run_expand_sessions(args)


def cmd_fix_builds(args):
  """Handle the fix-builds subcommand."""
  _run_sessions('fix-build', args)


def cmd_run_task(args):
  """Handle the run-task subcommand."""
  _run_sessions('free-task', args)


def cmd_add_chronos(args):
  """Handle the add-chronos-support subcommand."""
  _run_sessions('add-chronos', args)


def cmd_integrate_project(args):
  """Handle the integrate-project subcommand."""
  _run_integrate_sessions(args)


def cmd_show_prompt(args):
  """Handle the show-prompt subcommand."""
  task = args.task
  task_description = getattr(args, 'task_description', None)
  total_rounds = getattr(args, 'rounds', 1) if task == 'expand' else 1
  expansion_size = getattr(args, 'expansion_size', 'medium')
  for project in args.projects:
    if not os.path.isdir(os.path.join(OSS_FUZZ_ROOT, 'projects', project)):
      print(f'[!] Warning: projects/{project}/ does not exist', file=sys.stderr)
    for round_num in range(1, total_rounds + 1):
      print_prompt(task,
                   project,
                   task_description=task_description,
                   round_num=round_num,
                   total_rounds=total_rounds,
                   expansion_size=expansion_size)


def main():
  parser = argparse.ArgumentParser(
      description='Launch agent sessions to work on OSS-Fuzz projects.',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent("""\
            Examples:
              # Expand three projects in parallel (single round, medium size):
              python %(prog)s expand-oss-fuzz-projects open62541 json-c htslib

              # Run 3 rounds of expansion, aiming for 5+ harnesses each round
              # (summary agent runs automatically after all rounds):
              python %(prog)s expand-oss-fuzz-projects --rounds 3 --expansion-size large open62541

              # Single focused harness per project (no summary by default):
              python %(prog)s expand-oss-fuzz-projects --expansion-size small json-c htslib

              # Force a summary even for a single round:
              python %(prog)s expand-oss-fuzz-projects --summary open62541

              # Multi-round without the summary agent:
              python %(prog)s expand-oss-fuzz-projects --rounds 3 --no-summary open62541

              # Force consolidation even for a single round:
              python %(prog)s expand-oss-fuzz-projects --consolidate open62541

              # Multi-round skipping consolidation:
              python %(prog)s expand-oss-fuzz-projects --rounds 3 --no-consolidate open62541

              # Fix broken builds for two projects:
              python %(prog)s fix-builds open62541 json-c

              # Run a free-form task on one or more projects:
              python %(prog)s run-task \\
                  --task-description "Investigate why the XML parser harness \\
                      has low branch coverage and add targeted harnesses for \\
                      the attribute-parsing paths." \\
                  open62541 json-c

              # Just print the prompt without running an agent:
              python %(prog)s expand-oss-fuzz-projects --print-only open62541
              python %(prog)s fix-builds --print-only open62541
              python %(prog)s run-task --print-only \\
                  --task-description "Check seed corpus quality." open62541

              # Add Chronos support (replay_build.sh + run_tests.sh):
              python %(prog)s add-chronos-support open62541 json-c htslib

              # Integrate a new project from its repository URL:
              python %(prog)s integrate-project https://github.com/owner/repo

              # Integrate multiple projects in parallel:
              python %(prog)s integrate-project \\
                  https://github.com/owner/repo1 \\
                  https://github.com/owner/repo2

              # Preview the integration prompt without running an agent:
              python %(prog)s integrate-project --print-only \\
                  https://github.com/owner/repo

              # Use a specific agent CLI:
              python %(prog)s expand-oss-fuzz-projects --agent gemini htslib

              # Show the prompt for a project:
              python %(prog)s show-prompt --task expand open62541
              python %(prog)s show-prompt --task fix-build open62541
              python %(prog)s show-prompt --task free-task \\
                  --task-description "Audit harness threat models." open62541
        """),
  )

  subparsers = parser.add_subparsers(dest='command', required=True)

  # Shared arguments for session-launching subcommands.
  session_args = argparse.ArgumentParser(add_help=False)
  session_args.add_argument(
      'projects',
      nargs='+',
      help='One or more OSS-Fuzz project names (directories under '
      'projects/).',
  )
  session_args.add_argument(
      '--agent',
      choices=SUPPORTED_AGENTS,
      default=None,
      help='Agent CLI to use (default: auto-detect).',
  )
  session_args.add_argument(
      '--print-only',
      action='store_true',
      help='Print the prompts without launching agent sessions.',
  )
  session_args.add_argument(
      '-j',
      '--max-parallel',
      type=int,
      default=DEFAULT_MAX_PARALLEL,
      help='Maximum number of agent sessions to run in parallel '
      f'(default: {DEFAULT_MAX_PARALLEL}).',
  )

  # expand-oss-fuzz-projects
  expand_parser = subparsers.add_parser(
      'expand-oss-fuzz-projects',
      parents=[session_args],
      help='Launch agent sessions to expand fuzzing coverage of OSS-Fuzz '
      'projects.',
  )
  expand_parser.add_argument(
      '--rounds',
      type=int,
      default=1,
      metavar='N',
      help='Number of expansion rounds to run per project (default: 1). '
      'Rounds run sequentially; each round reads the previous round\'s '
      'report and targets different code areas.',
  )
  expand_parser.add_argument(
      '--expansion-size',
      choices=list(EXPAND_SIZE_GUIDANCE.keys()),
      default='medium',
      help='How many harnesses the agent should aim to add per round: '
      'small=1, medium=2-3 (default), large=5+.',
  )
  consolidate_group = expand_parser.add_mutually_exclusive_group()
  consolidate_group.add_argument(
      '--consolidate',
      dest='consolidate',
      action='store_true',
      default=None,
      help='Run a consolidation agent after all rounds complete to remove '
      'redundant harnesses and merge high-overlap ones (default: on when '
      '--rounds > 1, off for a single round).',
  )
  consolidate_group.add_argument(
      '--no-consolidate',
      dest='consolidate',
      action='store_false',
      help='Skip the consolidation agent even when running multiple rounds.',
  )
  summary_group = expand_parser.add_mutually_exclusive_group()
  summary_group.add_argument(
      '--summary',
      dest='summary',
      action='store_true',
      default=None,
      help='Run a summary agent after all rounds complete (default: on when '
      '--rounds > 1, off for a single round).',
  )
  summary_group.add_argument(
      '--no-summary',
      dest='summary',
      action='store_false',
      help='Skip the summary agent even when running multiple rounds.',
  )
  expand_parser.set_defaults(func=cmd_expand)

  # fix-builds
  fix_parser = subparsers.add_parser(
      'fix-builds',
      parents=[session_args],
      help='Launch agent sessions to fix broken OSS-Fuzz project builds.',
  )
  fix_parser.set_defaults(func=cmd_fix_builds)

  # run-task
  run_task_parser = subparsers.add_parser(
      'run-task',
      parents=[session_args],
      help='Launch agent sessions to carry out a free-form task on OSS-Fuzz '
      'projects.',
  )
  run_task_parser.add_argument(
      '--task-description',
      required=True,
      metavar='TEXT',
      help='Free-form description of the task for the agent to perform.',
  )
  run_task_parser.set_defaults(func=cmd_run_task)

  # add-chronos-support
  chronos_parser = subparsers.add_parser(
      'add-chronos-support',
      parents=[session_args],
      help='Launch agent sessions to add Chronos support (replay_build.sh '
      'and run_tests.sh) to OSS-Fuzz projects.',
  )
  chronos_parser.set_defaults(func=cmd_add_chronos)

  # integrate-project
  integrate_parser = subparsers.add_parser(
      'integrate-project',
      help='Launch agent sessions to integrate new projects into OSS-Fuzz '
      'from source URLs.',
  )
  integrate_parser.add_argument(
      'urls',
      nargs='+',
      metavar='URL',
      help='One or more URLs of open source projects to integrate '
      '(e.g. https://github.com/owner/repo).',
  )
  integrate_parser.add_argument(
      '--agent',
      choices=SUPPORTED_AGENTS,
      default=None,
      help='Agent CLI to use (default: auto-detect).',
  )
  integrate_parser.add_argument(
      '--print-only',
      action='store_true',
      help='Print the prompts without launching agent sessions.',
  )
  integrate_parser.add_argument(
      '-j',
      '--max-parallel',
      type=int,
      default=DEFAULT_MAX_PARALLEL,
      help='Maximum number of agent sessions to run in parallel '
      f'(default: {DEFAULT_MAX_PARALLEL}).',
  )
  integrate_parser.set_defaults(func=cmd_integrate_project)

  # show-prompt
  show_parser = subparsers.add_parser(
      'show-prompt',
      help='Print the agent prompt for a project without running anything.',
  )
  show_parser.add_argument('projects',
                           nargs='+',
                           help='OSS-Fuzz project names.')
  show_parser.add_argument(
      '--task',
      choices=['expand', 'fix-build', 'free-task', 'add-chronos'],
      default='expand',
      help='Which task prompt to show (default: expand).',
  )
  show_parser.add_argument(
      '--task-description',
      metavar='TEXT',
      default=None,
      help='Task description (required when --task=free-task).',
  )
  show_parser.add_argument(
      '--rounds',
      type=int,
      default=1,
      metavar='N',
      help='Number of rounds to show prompts for (expand task only).',
  )
  show_parser.add_argument(
      '--expansion-size',
      choices=list(EXPAND_SIZE_GUIDANCE.keys()),
      default='medium',
      help='Expansion size to use in the shown prompt (expand task only).',
  )
  show_parser.set_defaults(func=cmd_show_prompt)

  args = parser.parse_args()
  args.func(args)


if __name__ == '__main__':
  main()
