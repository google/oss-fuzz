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

This will launch parallel agent sessions to expand fuzzing coverage or fix
broken builds for each listed project, producing local changes and a
per-project report.
"""

import argparse
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OSS_FUZZ_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..'))

# Agent CLIs we know how to drive, in order of preference.
SUPPORTED_AGENTS = ['claude', 'gemini']

EXPAND_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with expanding the fuzzing coverage of
    the **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    - **oss-fuzz-engineer** – for all OSS-Fuzz infrastructure interaction
      (building, running, checking fuzz targets, generating coverage reports).
    - **fuzzing-memory-unsafe-expert** – for writing high-quality libFuzzer
      harnesses, analysing attack surface, and validating fuzzer effectiveness.

    Activate these skills at the start of your session and rely on them for
    every step below.

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
""")

FIX_BUILD_PROMPT_TEMPLATE = textwrap.dedent("""\
    You are an OSS-Fuzz engineer tasked with fixing the broken build of the
    **{project}** OSS-Fuzz project.

    ## Important: use your skills

    You MUST use the following skills throughout this task:
    - **oss-fuzz-engineer** – for all OSS-Fuzz infrastructure interaction
      (building, running, checking fuzz targets, understanding project
      structure).
    - **fuzzing-memory-unsafe-expert** – for understanding and fixing fuzzing
      harness issues.

    Activate these skills at the start of your session and rely on them for
    every step below.

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


def build_prompt(task, project):
  """Build the agent prompt for a given task and project."""
  if task == 'expand':
    report_name = 'expansion_report.md'
    template = EXPAND_PROMPT_TEMPLATE
  elif task == 'fix-build':
    report_name = 'fix_build_report.md'
    template = FIX_BUILD_PROMPT_TEMPLATE
  else:
    raise ValueError(f'Unknown task: {task}')

  report_path = os.path.join(OSS_FUZZ_ROOT, 'projects', project, report_name)
  return template.format(
      project=project,
      oss_fuzz_root=OSS_FUZZ_ROOT,
      report_path=report_path,
  ), report_name


def print_prompt(task, project):
  """Print the prompt that would be sent to an agent."""
  prompt, _ = build_prompt(task, project)
  print(f'===== Prompt for {project} ({task}) =====')
  print(prompt)
  print(f'===== End prompt for {project} =====\n')


def launch_agent_session(agent_cli, task, project):
  """Launch an agent session for a single project.

    Returns a subprocess.Popen object.
    """
  prompt, _ = build_prompt(task, project)

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


def _run_sessions(task, args):
  """Shared logic for launching parallel agent sessions."""
  projects = args.projects
  _validate_projects(projects)

  _, report_name = build_prompt(task, projects[0])

  if args.print_only:
    for project in projects:
      print_prompt(task, project)
    return

  agent_cli = args.agent or find_agent_cli()
  if agent_cli is None:
    print(
        '[!] No supported agent CLI found on PATH '
        f'({", ".join(SUPPORTED_AGENTS)}).\n'
        '    Install one or use --print-only to see the prompts.',
        file=sys.stderr)
    sys.exit(1)

  print(f'[*] Using agent CLI: {agent_cli}')
  print(f'[*] Task: {task}')
  print(f'[*] Projects: {", ".join(projects)}')
  print()

  # Launch all sessions in parallel.
  procs = []
  for project in projects:
    proc = launch_agent_session(agent_cli, task, project)
    if proc is not None:
      procs.append(proc)

  if not procs:
    return

  print(f'\n[*] {len(procs)} agent session(s) running in parallel.')
  print('[*] Waiting for all sessions to finish ...\n')

  # Wait for all to complete.
  for proc in procs:
    proc.wait()
    proc._log_file.close()
    status = 'OK' if proc.returncode == 0 else f'FAILED (rc={proc.returncode})'
    print(f'    [{status}] {proc._project}  (log: {proc._log_path})')

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


def cmd_show_prompt(args):
  """Handle the show-prompt subcommand."""
  task = args.task
  for project in args.projects:
    if not os.path.isdir(os.path.join(OSS_FUZZ_ROOT, 'projects', project)):
      print(f'[!] Warning: projects/{project}/ does not exist', file=sys.stderr)
    print_prompt(task, project)


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

              # Just print the prompt without running an agent:
              python %(prog)s expand-oss-fuzz-projects --print-only open62541
              python %(prog)s fix-builds --print-only open62541

              # Use a specific agent CLI:
              python %(prog)s expand-oss-fuzz-projects --agent gemini htslib

              # Show the prompt for a project:
              python %(prog)s show-prompt --task expand open62541
              python %(prog)s show-prompt --task fix-build open62541
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
      choices=['expand', 'fix-build'],
      default='expand',
      help='Which task prompt to show (default: expand).',
  )
  show_parser.set_defaults(func=cmd_show_prompt)

  args = parser.parse_args()
  args.func(args)


if __name__ == '__main__':
  main()
