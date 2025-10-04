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


def generate_final_summary(all_results):
  """Prints a visually appealing summary of all build versions."""
  summary_lines = [
      '╔═════════════════════════════════════════════════════════════════════════════╗',
      '║                             FINAL BUILD REPORT                              ║',
      '╠═════════════════════════════════════════════════════════════════════════════╣',
  ]
  for version, data in all_results.items():
    if data:
      line = (f"║ {version.ljust(15)} ► Passed: {data['successful']} | "
              f"Failed: {data['failed']} | Skipped: {data['skipped']} | "
              f"Total: {data['total']}     ║")
      summary_lines.append(line)
  summary_lines.append(
      '╚═════════════════════════════════════════════════════════════════════════════╝'
  )
  print('\n'.join(summary_lines))


def generate_comparison_table(all_results):
  """Prints a Markdown table comparing failures across versions."""
  all_failed_projects = set()
  for data in all_results.values():
    if data:
      all_failed_projects.update(data['failed_projects'])

  if not all_failed_projects:
    print('\n✅ No projects failed on any version. Great success!')
    return

  header = ('| Project        | Legacy | Ubuntu 20.04 | Ubuntu 24.04 |\n'
            '| :------------- | :----: | :----------: | :----------: |')
  table_rows = [header]

  for project in sorted(list(all_failed_projects)):
    row = f'| `{project}` |'
    for version in RESULT_FILES:
      if (all_results[version] and
          project in all_results[version]['failed_projects']):
        row += ' ❌ |'
      else:
        row += ' ✅ |'
    table_rows.append(row)

  print('\n### Failure Comparison Table\n')
  print('\n'.join(table_rows))


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