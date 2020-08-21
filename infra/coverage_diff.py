#!/usr/bin/env python
# Copyright 2020 Google Inc.
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

"""Generate a coverage report on local changes to an OSS-Fuzz project.
This script starts for an empty corpus and runs fuzzers for <fuzz_time>
seconds to generate one. It does not use the existing corpus in OSS-Fuzz,
as no corpus for new fuzzers will exist locally. The JSON coverage outputs
will be placed in oss-fuzz/coverage_reports/detailed/<project_name>.

The --comparison flag will not compare coverage results with those in
google:master. This is used when the project does not already exist upstream.

The --file-output flag will flush a summary of the results to
disk for more permanent storage, if required. This will be placed at
oss-fuzz/coverage_reports/<project_name>_coverage.txt

Optional: place a corpus for the project in oss-fuzz/corpora/<project_name>.
This corpus will be used as a basis for each fuzzer's individual corpus.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

import helper

OSS_FUZZ_DIR = helper.OSS_FUZZ_DIR

def main():
  """Get subcommands from program arguments and generate coverage report(s)."""

  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(helper.BUILD_DIR):
    os.mkdir(helper.BUILD_DIR)

  parser = argparse.ArgumentParser('coverage_diff.py',
                                   description='oss-fuzz coverage diff helper')
  parser.add_argument('project_name')
  parser.add_argument('fuzz_time')

  parser.add_argument('--comparison', action='store_true',
                      help='Compare local coverage to Google\'s HEAD.')
  parser.add_argument('--no-comparison', action='store_true',
                      help='Don\'t compare local coverage to Google\'s HEAD')

  parser.add_argument('--file-output', action='store_true',
                      help='Flush coverage results to disk.')
  parser.add_argument('--no-file-output', action='store_true',
                      help='Don\'t flush coverage results to disk.')

  parser.set_defaults(comparison=True, file_output=False)

  args = parser.parse_args()

  if not helper.check_project_exists(args.project_name):
    return 1

  args.fuzz_time = float(args.fuzz_time)
  setup(args)

  if args.comparison:
    os.system('git clone https://github.com/google/oss-fuzz')
    os.chdir('oss-fuzz')
    generate_coverage_report(args, 'original')
    os.chdir(OSS_FUZZ_DIR)
    shutil.rmtree('oss-fuzz')

  os.chdir(OSS_FUZZ_DIR)
  generate_coverage_report(args, 'modified')

  print(args.result)

  if args.file_output:
    with open(args.out_file, 'w') as out:
      out.write(args.result)

  return 0

def clean_dirs(project_name):
  """Cleans directories related to coverage report generation."""

  to_clean = [
      './build/out/{}'.format(project_name),
      './build/work/{}'.format(project_name),
      './build/corpus/{}'.format(project_name),
      './coverage_reports/detailed/{}'.format(project_name),
      './oss-fuzz'
  ]

  for directory in to_clean:
    shutil.rmtree(directory, ignore_errors=True)

  try:
    os.remove('./coverage_reports/{}_coverage.txt'.format(project_name))
  except FileNotFoundError:
    pass

def setup(args):
  """Adds relevant paths for report generation to args. We add a path to the
  project corpus if it exists, a path to place the detailed coverage report
  JSON files in, and a path to place the summary if --file-output is enabled.
  We also set the header for the result string.
  """

  clean_dirs(args.project_name)

  corpus_dir = './corpora/{}_corpus'.format(args.project_name)
  if not os.path.isdir('./corpora') or not os.path.isdir(corpus_dir):
    corpus_dir = ''

  out_dir = './coverage_reports/detailed/{}'.format(args.project_name)
  os.makedirs(out_dir, exist_ok=True)

  out_file = './coverage_reports/{}_coverage.txt'.format(args.project_name)

  args.result = '{} coverage\n'.format(args.project_name)
  args.local_corpus_dir = os.path.join(OSS_FUZZ_DIR, corpus_dir)
  args.out_dir = os.path.join(OSS_FUZZ_DIR, out_dir)
  args.out_file = os.path.join(OSS_FUZZ_DIR, out_file)

def format_report(report_path, report_version, args):
  """Get coverage summary from generated JSON and append it to the result
  string. If --file-output is enabled, this result will be flushed to the
  summary file at oss-fuzz/coverage_reports/<project_name>_coverage.txt.
  """

  with open(report_path, 'r') as report:
    f_data = json.load(report)
    region_data = f_data['data'][0]['totals']['regions']

  output_format = '{0}: {1}/{2} regions - {3}% coverage\n'
  args.result += (output_format.format(
      report_version,
      region_data['covered'],
      region_data['count'],
      region_data['percent']))

def generate_corpus(args, fuzzer):
  """Run fuzzers for the specified time in order to generate a local corpus.
  We get <fuzz_time> (in seconds) as an argument when running this script. It
  is stored in the args namespace.
  """

  fuzzer_corpus_dir = './build/corpus/{0}/{1}'.format(args.project_name, fuzzer)
  os.mkdir(fuzzer_corpus_dir)
  fuzz_command = ['./build/out/{0}/{1}'.format(args.project_name, fuzzer),
                  fuzzer_corpus_dir, args.local_corpus_dir]

  try:
    subprocess.run(fuzz_command, check=False, timeout=args.fuzz_time)
  except subprocess.TimeoutExpired:
    pass

def generate_coverage_report(args, build_type): # pylint: disable-msg=too-many-locals
  """Generate coverage report for a given fuzzer build. We first build
  the fuzzers with ASan enabled to generate the corpus used for coverage.
  Then, we build the fuzzers a second time with the coverage sanitizer
  so we can generate the report.
  """

  if not os.path.isdir('./build'):
    os.mkdir('./build')

  required_directories = ['./build/out', './build/corpus']
  for directory in required_directories:
    if not os.path.isdir(directory):
      os.mkdir(directory)
    project_dir = os.path.join(directory, args.project_name)
    if not os.path.isdir(project_dir):
      os.mkdir(project_dir)

  build_image_tokens = ['python3', 'infra/helper.py', 'build_image',
                        '--pull', '{}']
  build_image_cmd = ' '.join(build_image_tokens).format(args.project_name)

  build_fuzzers_tokens = ['python3', 'infra/helper.py', 'build_fuzzers', '{}']
  build_fuzzers_cmd = ' '.join(build_fuzzers_tokens).format(args.project_name)

  os.system(build_image_cmd.format(args.project_name))
  os.system(build_fuzzers_cmd.format(args.project_name))

  out_dir = './build/out/{}'.format(args.project_name)
  out_dir_file_list = os.listdir(out_dir)
  fuzzer_list = [file for file in out_dir_file_list if '.' not in file]

  print('\nRunning fuzzers...')
  for fuzzer in fuzzer_list:
    generate_corpus(args, fuzzer)

  build_fuzzers_tokens = ['python3', 'infra/helper.py', 'build_fuzzers',
                          '--sanitizer=coverage', '{}']
  build_fuzzers_cmd = ' '.join(build_fuzzers_tokens).format(args.project_name)

  coverage_tokens = ['python3', 'infra/helper.py', 'coverage',
                     '--port=""', '--no-corpus-download', '{}']
  coverage_cmd = ' '.join(coverage_tokens).format(args.project_name)

  os.system(build_fuzzers_cmd)
  os.system(coverage_cmd)

  report_path_structure = './build/out/{}/report/linux/summary.json'
  report_path = report_path_structure.format(args.project_name)
  detailed_out_path = '{0}/{1}_summary_{2}.json'.format(
      args.out_dir, args.project_name, build_type)
  open(detailed_out_path, 'w').close()

  shutil.copyfile(report_path, detailed_out_path)
  format_report(detailed_out_path, build_type, args)

if __name__ == '__main__':
  sys.exit(main())
