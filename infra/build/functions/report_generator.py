# Copyright 2025 Google LLC
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
#
################################################################################
"""Generates a comparative report of trial build results and determines the
final status of the pipeline."""

import json
import os
import sys

# Define the expected result files for each build version.
RESULT_FILES = {
    'Legacy': 'legacy-results.json',
    'Ubuntu 20.04': 'ubuntu-20-04-results.json',
    'Ubuntu 24.04': 'ubuntu-24-04-results.json',
}


def _print_box(title, lines):
  """Prints a formatted box with a title and lines."""
  box_width = 92
  title_line = f'| {title.center(box_width - 4)} |'
  summary_lines = [
      '+' + '-' * (box_width - 2) + '+',
      title_line,
      '+' + '-' * (box_width - 2) + '+',
  ]
  for line in lines:
    padding = box_width - 4 - len(line)
    summary_lines.append(f'| {line}{" " * padding} |')

  summary_lines.append('+' + '-' * (box_width - 2) + '+')
  print('\n'.join(summary_lines))


def generate_final_summary(all_results):
  """Prints a summary of all build versions."""
  box_width = 92
  summary_lines = []
  total_unique_projects = set()

  for version, data in all_results.items():
    if data:
      total_unique_projects.update(data.get('all_projects', []))
      passed = str(data.get('successful_builds', 0))
      failed = str(data.get('failed_builds', 0))
      skipped = str(data.get('skipped_builds', 0))
      total_builds = str(
          data.get('successful_builds', 0) + data.get('failed_builds', 0) +
          data.get('skipped_builds', 0))
      line = (
          f"  {version.ljust(15)} -> {'Passed:'.ljust(8)} {passed.ljust(6)} | "
          f"{'Failed:'.ljust(8)} {failed.ljust(6)} | {'Skipped:'.ljust(8)} {skipped.ljust(6)} | "
          f"{'Total:'.ljust(7)} {total_builds.ljust(6)}")
      summary_lines.append(line)

  if summary_lines:
    separator = '-' * (box_width - 4)
    summary_lines.append(separator)
    project_summary_line = (
        f"  Total Projects Analyzed: {len(total_unique_projects)}")
    summary_lines.append(project_summary_line)

  _print_box('FINAL BUILD REPORT', summary_lines)


def generate_comparison_table(all_results):
  """Prints a table comparing failures across versions."""
  all_projects = set()
  for data in all_results.values():
    if data and 'all_projects' in data:
      all_projects.update(data['all_projects'])

  if not all_projects:
    print('\nNo projects were run.')
    return

  project_col_width = 30
  header = ' Project                       |      Legacy      |   Ubuntu 20.04   |   Ubuntu 24.04'
  separator = '-------------------------------+------------------+------------------+------------------'

  table_lines = [header, separator]

  for project in sorted(list(all_projects)):
    project_name = project
    if len(project_name) > project_col_width:
      project_name = project_name[:project_col_width - 3] + '...'

    row = f' {project_name.ljust(project_col_width)}|'
    for version in RESULT_FILES:
      status_icon = ' '
      if all_results.get(version):
        if project in all_results[version].get('failed_projects', []):
          status_icon = 'FAIL'
        elif project in all_results[version].get('skipped_projects', []):
          status_icon = 'SKIP'
        else:
          status_icon = 'PASS'
      row += f' {status_icon.center(15)} |'
    row = row[:-1]
    table_lines.append(row)

  _print_box('FAILURE COMPARISON TABLE', table_lines)


def main():
  """Main function to generate report and determine pipeline status."""
  if os.path.exists('trial_build_skipped.flag'):
    print('Skipping report generation because trial build was not invoked.')
    sys.exit(0)

  all_results = {}
  any_failures = False
  any_results_found = False
  total_unique_projects = set()

  print('Generating final build report...')

  for version, filename in RESULT_FILES.items():
    if not os.path.exists(filename):
      print(f'Warning: Result file "{filename}" not found.')
      all_results[version] = None
      continue

    with open(filename, 'r') as f:
      data = json.load(f)
      all_results[version] = data
      any_results_found = True
      if data.get('failed_builds', 0) > 0:
        any_failures = True
      total_unique_projects.update(data.get('all_projects', []))

  if not any_results_found:
    error_lines = [
        'No result files found. This typically means that all upstream builds',
        'either timed out or failed catastrophically.',
    ]
    _print_box('FINAL BUILD REPORT', error_lines)
    print('\nPipeline finished with failures.')
    sys.exit(1)

  generate_comparison_table(all_results)
  generate_final_summary(all_results)

  has_explicit_failures = any_failures
  no_projects_were_run = any_results_found and not total_unique_projects

  if has_explicit_failures or no_projects_were_run:
    if no_projects_were_run and not has_explicit_failures:
      print(
          '\nWarning: No projects were run. This may indicate an upstream issue.'
      )
    print('\nPipeline finished with failures.')
    sys.exit(1)

  print('\nPipeline finished successfully.')
  sys.exit(0)


if __name__ == '__main__':
  main()
