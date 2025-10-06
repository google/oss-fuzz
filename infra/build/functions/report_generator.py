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
import textwrap

# Define the expected result files for each build version.
RESULT_FILES = {
    'Legacy': 'legacy-results.json',
    'Ubuntu 20.04': 'ubuntu-20-04-results.json',
    'Ubuntu 24.04': 'ubuntu-24-04-results.json',
}


def _print_summary_box(title, lines):
  """Prints a formatted box for summarizing build results."""
  box_width = 80
  title_line = f'║ {title.center(box_width - 4)} ║'
  summary_lines = [
      '╔' + '═' * (box_width - 2) + '╗',
      title_line,
      '╠' + '═' * (box_width - 2) + '╣',
  ]
  for line in lines:
    wrapped_lines = textwrap.wrap(line, box_width - 6)
    for i, sub_line in enumerate(wrapped_lines):
      summary_lines.append(f'║  {sub_line.ljust(box_width - 6)}  ║')
  summary_lines.append('╚' + '═' * (box_width - 2) + '╝')
  print('\n'.join(summary_lines))


def generate_final_summary(all_results):
  """Prints a visually appealing summary of all build versions."""
  summary_lines = []
  for version, data in all_results.items():
    if data:
      line = (
          f"  {version.ljust(15)} ► Passed: {data['successful']} | "
          f"Failed: {data['failed']} | Skipped: {data['skipped']} | "
          f"Total: {data['total']}")
      summary_lines.append(line)

  _print_summary_box('FINAL BUILD REPORT', summary_lines)


def generate_comparison_table(all_results):
  """Prints a table comparing failures across versions."""
  all_projects = set()
  for data in all_results.values():
    if data and 'all_projects' in data:
      all_projects.update(data['all_projects'])

  if not all_projects:
    print('\n✅ No projects were run.')
    return

  table_rows = []
  header = ('Project'.ljust(20) + '| ' + 'Legacy'.center(15) + '| ' +
            'Ubuntu 20.04'.center(15) + '| ' + 'Ubuntu 24.04'.center(15))
  separator = ('-' * 21 + '+' + '-' * 17 + '+' + '-' * 17 + '+' + '-' * 17)
  table_rows.append(header)
  table_rows.append(separator)

  for project in sorted(list(all_projects)):
    row_parts = [f' {project.ljust(19)}']
    for version in RESULT_FILES:
      status_icon = '❓'
      if all_results.get(version):
        if project in all_results[version].get('failed_projects', []):
          status_icon = '❌'
        elif project in all_results[version].get('skipped_projects', []):
          status_icon = '➡️'
        else:
          status_icon = '✅'
      row_parts.append(f' {status_icon.center(15)} ')
    table_rows.append('|'.join(row_parts))

  _print_summary_box('FAILURE COMPARISON TABLE', table_rows)


def main():
  """Main function to generate report and determine pipeline status."""
  all_results = {}
  any_failures = False

  print('Generating final build report...')

  for version, filename in RESULT_FILES.items():
    if not os.path.exists(filename):
      print(f'Warning: Result file "{filename}" not found.')
      all_results[version] = None
      continue

    with open(filename, 'r') as f:
      data = json.load(f)
      all_results[version] = data
      if data['failed'] > 0:
        any_failures = True

  generate_comparison_table(all_results)
  generate_final_summary(all_results)

  if any_failures:
    print('\nPipeline finished with failures.')
    sys.exit(1)
  else:
    print('\nPipeline finished successfully.')
    sys.exit(0)


if __name__ == '__main__':
  main()
