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

This will launch parallel agent sessions to expand fuzzing coverage, fix
broken builds, or carry out an arbitrary task for each listed project,
producing local changes and a per-project report.
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

EXPAND_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with expanding the fuzzing coverage of
    the **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    {fuzzing_skills_blurb}

    Rely on them for every step below.

    ## Objective

    Expand the fuzzing posture of the **{project}** project by adding one or
    more new fuzzing harnesses (or meaningfully improving existing ones) so that
    code coverage increases. Focus on a single, well-justified improvement
    rather than many shallow changes.

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
       Generate a *before* coverage baseline and an *after* report:
       ```
       python3 infra/helper.py introspector --coverage-only --seconds 30 \\
           --out {project}-cov-before {project}
       ```
       (run this BEFORE making changes, using the original build)

       After your changes:
       ```
       python3 infra/helper.py introspector --coverage-only --seconds 30 \\
           --out {project}-cov-after {project}
       ```

       Compare the two and confirm that overall coverage did not regress. If it
       did, explain why the regression is acceptable. If you see no coverage
       improvement then go back to previous steps and try a different approach.
       You must continue iterating on steps 3-6 until you have clear improvements
       at hand.

    7. **Write a report**
       Create a file `{report_path}` containing:
       - Summary of changes made.
       - Rationale: why this area was chosen, what bugs it may find.
       - Coverage comparison (before vs. after).
       - Build / check_build / run_fuzzer output excerpts showing success.
       - Recommendations for further expansion.

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


def build_prompt(task, project, task_description=None):
  """Build the agent prompt for a given task and project."""
  if task == 'expand':
    report_name = 'expansion_report.md'
    template = EXPAND_PROMPT_TEMPLATE
  elif task == 'fix-build':
    report_name = 'fix_build_report.md'
    template = FIX_BUILD_PROMPT_TEMPLATE
  elif task == 'free-task':
    report_name = 'task_report.md'
    template = FREE_TASK_PROMPT_TEMPLATE
  else:
    raise ValueError(f'Unknown task: {task}')

  report_path = os.path.join(OSS_FUZZ_ROOT, 'projects', project, report_name)
  fmt_kwargs = dict(
      project=project,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      report_path=report_path,
      fuzzing_skills_blurb=FUZZING_SKILLS_BLURB,
  )
  if task_description is not None:
    fmt_kwargs['task_description'] = task_description
  return template.format(**fmt_kwargs), report_name


def print_prompt(task, project, task_description=None):
  """Print the prompt that would be sent to an agent."""
  prompt, _ = build_prompt(task, project, task_description=task_description)
  print(f'===== Prompt for {project} ({task}) =====')
  print(prompt)
  print(f'===== End prompt for {project} =====\n')


def launch_agent_session(agent_cli, task, project, task_description=None):
  """Launch an agent session for a single project.

    Returns a subprocess.Popen object.
    """
  prompt, _ = build_prompt(task, project, task_description=task_description)

  print(f'[*] Launching {agent_cli} session for project: {project} ({task})')

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
  log_path = os.path.join(
      log_dir, f'{project}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log')

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


def _run_single_session(agent_cli, task, project, task_description=None):
  """Launch an agent session and wait for it to complete.

  Returns a dict with the project name, return code, and log path.
  """
  proc = launch_agent_session(agent_cli,
                              task,
                              project,
                              task_description=task_description)
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


def cmd_expand(args):
  """Handle the expand-oss-fuzz-projects subcommand."""
  _run_sessions('expand', args)


def cmd_fix_builds(args):
  """Handle the fix-builds subcommand."""
  _run_sessions('fix-build', args)


def cmd_run_task(args):
  """Handle the run-task subcommand."""
  _run_sessions('free-task', args)


def cmd_integrate_project(args):
  """Handle the integrate-project subcommand."""
  _run_integrate_sessions(args)


def cmd_show_prompt(args):
  """Handle the show-prompt subcommand."""
  task = args.task
  task_description = getattr(args, 'task_description', None)
  for project in args.projects:
    if not os.path.isdir(os.path.join(OSS_FUZZ_ROOT, 'projects', project)):
      print(f'[!] Warning: projects/{project}/ does not exist', file=sys.stderr)
    print_prompt(task, project, task_description=task_description)


def main():
  parser = argparse.ArgumentParser(
      description='Launch agent sessions to work on OSS-Fuzz projects.',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent("""\
            Examples:
              # Expand three projects in parallel:
              python %(prog)s expand-oss-fuzz-projects open62541 json-c htslib

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
      choices=['expand', 'fix-build', 'free-task'],
      default='expand',
      help='Which task prompt to show (default: expand).',
  )
  show_parser.add_argument(
      '--task-description',
      metavar='TEXT',
      default=None,
      help='Task description (required when --task=free-task).',
  )
  show_parser.set_defaults(func=cmd_show_prompt)

  args = parser.parse_args()
  args.func(args)


if __name__ == '__main__':
  main()
