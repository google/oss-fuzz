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
"""""" # TODO(rjotwani): Add file description

import argparse
import helper
import json
import os
import shutil
import sys

OSS_FUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

# TODO(rjotwani): Write usage
def usage():
    return

def main():
  """Get subcommands from program arguments and generate coverage report."""

  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('coverage_diff.py', description='oss-fuzz coverage diffs')
  parser.add_argument('project_name')
  parser.add_argument('fuzz_time')
  parser.add_argument('--no-comparison', action='store_true')

  args = parser.parse_args()
  args.proj_corpus = 'test'

  # if not helper.check_project_exists(args.project_name):
  #   return 1

  corpus_dir, out_dir, out_file = setup(args.project_name)
  return generate_report(args)

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
  if not os.path.is_dir('./corpora') or not os.path.is_dir(corpus_dir):
    corpus_dir = ''

  out_dir = './coverage_reports/detailed/{}'.format(project_name)
  os.makedirs(out_dir, exist_ok=True)

  out_file = './coverage_reports/{}'.format(project_name)
  out = open(out_file, 'w')
  out.write('{} coverage\n'.format(project_name))
  out.close()

  return corpus_dir, out_dir, out_file

def generate_report(report_path, report_version, out_file):
  """Get coverage summary from generated JSON and flush it to the out file."""

  report = open(report_path, 'r')
  out = open(out_file, 'a')

  f = json.load(report)
  data = f['data'][0]['totals']['regions']

  out.write('{0}: {1}/{2} regions - {3}% coverage\n'.format(
      report_version, data['covered'], data['count'], data['percent']))

  report.close()
  out.close()

def get_coverage():
  pass

def generate_corpus(args):
  os.mkdir

if __name__ == '__main__':
  sys.exit(main())
