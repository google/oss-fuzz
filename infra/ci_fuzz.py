# Copyright 2020 Google LLC
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
"""Module used by CI tools in order to interact with fuzzers.
This module helps CI tools do the following
  1. build fuzzers
  2. run fuzzers
Eventually it will be used to help CI tools determine which fuzzers to run.
"""

import argparse
import os
import tempfile

import build_specified_commit
import utils


def main():
  """Connects Fuzzers with CI tools."""
  parser = argparse.ArgumentParser(
      description='Help CI tools manage specific fuzzers.')

  subparsers = parser.add_subparsers(dest='command')
  build_fuzzer_parser = subparsers.add_parser(
      'build_fuzzers', help='Build an OSS-Fuzz projects fuzzers.')
  build_fuzzer_parser.add_argument('project_name')
  build_fuzzer_parser.add_argument('repo_url')
  build_fuzzer_parser.add_argument('commit_sha')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzers', help='Run an OSS-Fuzz projects fuzzers.')
  run_fuzzer_parser.add_argument('project_name')

  args = parser.parse_args()
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != os.path.dirname(utils.OSS_FUZZ_HOME):
    os.chdir(utils.OSS_FUZZ_HOME)
  if args.command == 'build_fuzzers':
    return build_fuzzers(args)
  elif args.command == 'run_fuzzer':
    return run_fuzzers(args)
  print('Invalid argument option, use  build_fuzzers or run_fuzzer.')
  return 1


def build_fuzzers(args):
  """Builds all of the fuzzers for a specific OSS-Fuzz project."""

  # TODO: Fix return value bubble to actually handle errors.
  with tempfile.TemporaryDirectory() as tmp_dir:
    print("Detecting repo with url: " + args.repo_url)
    return build_specified_commit.build_fuzzers_from_commit(
        args.project_name, args.commit_sha, tmp_dir, args.repo_url)


def run_fuzzers(args):
  """Runs a specific fuzzer for a specific OSS-Fuzz project."""
  return 0


if __name__ == '__main__':
  main()
