#!/usr/bin/env python3
# Copyright 2023 Google LLC
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
"""Helper script for creating a llvm-cov style JSON summary from a nyc
JSON summary."""
import json
import sys


def convert(nyc_json_summary):
  """Turns a nyc JSON report into a llvm-cov JSON summary."""
  summary = {
      'type':
          'oss-fuzz.javascript.coverage.json.export',
      'version':
          '1.0.0',
      'data': [{
          'totals':
              file_summary(nyc_json_summary['total']),
          'files': [{
              'filename': src_file,
              'summary': file_summary(nyc_json_summary[src_file])
          } for src_file in nyc_json_summary if src_file != 'total'],
      }],
  }

  return json.dumps(summary)


def file_summary(nyc_file_summary):
  """Returns a summary for a given file in the nyc JSON summary report."""
  return {
      'functions': element_summary(nyc_file_summary['functions']),
      'lines': element_summary(nyc_file_summary['lines']),
      'regions': element_summary(nyc_file_summary['branches'])
  }


def element_summary(element):
  """Returns a summary of a coverage element in the nyc JSON summary
  of the file"""
  return {
      'count': element['total'],
      'covered': element['covered'],
      'notcovered': element['total'] - element['covered'] - element['skipped'],
      'percent': element['pct'] if element['pct'] != 'Unknown' else 0
  }


def main():
  """Produces a llvm-cov style JSON summary from a nyc JSON summary."""
  if len(sys.argv) != 3:
    sys.stderr.write('Usage: %s <path_to_nyc_json_summary> <out_path_json>\n' %
                     sys.argv[0])
    return 1

  with open(sys.argv[1], 'r') as nyc_json_summary_file:
    nyc_json_summary = json.load(nyc_json_summary_file)
  json_summary = convert(nyc_json_summary)
  with open(sys.argv[2], 'w') as json_output_file:
    json_output_file.write(json_summary)

  return 0


if __name__ == '__main__':
  sys.exit(main())
