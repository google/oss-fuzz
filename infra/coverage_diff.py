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

"""
Generate a coverage report on local changes to an OSS-Fuzz project.
This script starts for an empty corpus and runs fuzzers for <fuzz_time>
seconds to generate one. It does not use the existing corpus in OSS-Fuzz,
as no corpus for new fuzzers will exist locally.

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

OSS_FUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

def main():
  """Get subcommands from program arguments and generate coverage report."""

  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('coverage_diff.py',
                                   description='oss-fuzz coverage diff helper')
  parser.add_argument('project_name')
  parser.add_argument('fuzz_time')
  parser.add_argument('--no-comparison', action='store_true')

  args = parser.parse_args()

  if not helper.check_project_exists(args.project_name):
    return 1

  args.port = ''
  args.engine = 'libfuzzer'
  args.architecture = 'x86_64'
  args.e = None
  args.source_path = None
  args.corpus_dir = None
  args.fuzz_target = None
  args.pull = True
  args.no_pull = False
  args.clean = True
  args.no_corpus_download = True
  args.extra_args = []
  args.fuzz_time = float(args.fuzz_time)
  args.local_corpus_dir, args.out_dir, args.out_file = setup(args.project_name)

  if not args.no_comparison:
    os.system('git clone https://github.com/google/oss-fuzz')
    os.chdir('oss-fuzz')
    get_coverage(args, 'original')
    os.chdir(OSS_FUZZ_DIR)
    shutil.rmtree('oss-fuzz')

  os.chdir(OSS_FUZZ_DIR)
  get_coverage(args, 'modified')

  print('\n')
  out = open(args.out_file)
  print(out.read())
  out.close()
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

def setup(project_name):
  """Returns relevant paths for report generation."""

  clean_dirs(project_name)

  corpus_dir = './corpora/{}_corpus'.format(project_name)
  if not os.path.isdir('./corpora') or not os.path.isdir(corpus_dir):
    corpus_dir = ''

  out_dir = './coverage_reports/detailed/{}'.format(project_name)
  os.makedirs(out_dir, exist_ok=True)

  out_file = './coverage_reports/{}_coverage.txt'.format(project_name)
  out = open(out_file, 'w')
  out.write('{} coverage\n'.format(project_name))
  out.close()

  return (os.path.join(OSS_FUZZ_DIR, corpus_dir),
          os.path.join(OSS_FUZZ_DIR, out_dir),
          os.path.join(OSS_FUZZ_DIR, out_file))

def generate_report(report_path, report_version, out_file):
  """Get coverage summary from generated JSON and flush it to the out file."""

  report = open(report_path, 'r')
  out = open(out_file, 'a')

  f_data = json.load(report)
  region_data = f_data['data'][0]['totals']['regions']

  output_format = '{0}: {1}/{2} regions - {3}% coverage\n'
  out.write(output_format.format(
      report_version,
      region_data['covered'],
      region_data['count'],
      region_data['percent']))

  report.close()
  out.close()

def generate_corpus(args, fuzzer):
  """Run fuzzers for the specified time in order to generate a local corpus."""

  corpus_name = '{}_corpus'.format(fuzzer)
  os.mkdir(corpus_name)
  os.mkdir('./build/corpus/{0}/{1}'.format(args.project_name, fuzzer))
  fuzz_command = ['./build/out/{0}/{1}'.format(args.project_name, fuzzer),
                  corpus_name, args.local_corpus_dir]

  try:
    subprocess.run(fuzz_command, check=False, timeout=args.fuzz_time)
  except subprocess.TimeoutExpired:
    pass

  for file in os.listdir(corpus_name):
    source_path = os.path.join(corpus_name, file)
    dest_path = './build/corpus/{0}/{1}'.format(
        args.project_name, fuzzer)
    shutil.copy(source_path, dest_path)

  shutil.rmtree(corpus_name)

def get_coverage(args, build_type): # pylint: disable-msg=too-many-locals
  """Generate coverage report for a given fuzzer build."""

  if not os.path.isdir('./build'):
    os.mkdir('./build')

  required_directories = ['./build/out', './build/corpus']
  for directory in required_directories:
    if not os.path.isdir(directory):
      os.mkdir(directory)
    project_dir = os.path.join(directory, args.project_name)
    if not os.path.isdir(project_dir):
      os.mkdir(project_dir)

  build_image_cmd = 'sudo python3 infra/helper.py build_image --pull {}'
  build_fuzzers_cmd = 'sudo python3 infra/helper.py build_fuzzers {}'
  os.system(build_image_cmd.format(args.project_name))
  os.system(build_fuzzers_cmd.format(args.project_name))

  out_dir = './build/out/{}'.format(args.project_name)
  out_dir_file_list = os.listdir(out_dir)
  fuzzer_list = [file for file in out_dir_file_list if '.' not in file]

  print('\nRunning fuzzers...')
  for fuzzer in fuzzer_list:
    generate_corpus(args, fuzzer)

  build_fuzzers_tokens = ['sudo', 'python3', 'infra/helper.py', 'build_fuzzers',
                          '--sanitizer=coverage', '{}']
  build_fuzzers_cmd = ' '.join(build_fuzzers_tokens).format(args.project_name)

  coverage_tokens = ['sudo', 'python3', 'infra/helper.py', 'coverage',
                     '--port=""', '--no-corpus-download', '{}']
  coverage_cmd = ' '.join(coverage_tokens).format(args.project_name)

  os.system(build_fuzzers_cmd)
  os.system(coverage_cmd)

  report_path_structure = './build/out/{}/report/linux/summary.json'
  report_path = report_path_structure.format(args.project_name)
  detailed_out_path = '{0}/{1}_summary_{2}.json'.format(
      args.out_dir, args.project_name, build_type)
  detailed_out_file = open(detailed_out_path, 'w')
  detailed_out_file.close()

  shutil.copyfile(report_path, detailed_out_path)
  generate_report(detailed_out_path, build_type, args.out_file)

if __name__ == '__main__':
  sys.exit(main())
