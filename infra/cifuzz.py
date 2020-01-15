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
This module helps CI tools do the following:
  1. Build fuzzers.
  2. Run fuzzers.
Eventually it will be used to help CI tools determine which fuzzers to run.
"""

import argparse
import os
import tempfile

import build_specified_commit
import repo_manager
import helper


def main():
  """Connects Fuzzers with CI tools.

  Returns:
    True on success False on failure.
  """
  parser = argparse.ArgumentParser(
      description='Help CI tools manage specific fuzzers.')

  subparsers = parser.add_subparsers(dest='command')
  build_fuzzer_parser = subparsers.add_parser(
      'build_fuzzers', help='Build an OSS-Fuzz projects fuzzers.')
  build_fuzzer_parser.add_argument('project_name')
  build_fuzzer_parser.add_argument('repo_name')
  build_fuzzer_parser.add_argument('commit_sha')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzers', help='Run an OSS-Fuzz projects fuzzers.')
  run_fuzzer_parser.add_argument('project_name')
  args = parser.parse_args()

  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)

  if args.command == 'build_fuzzers':
    return build_fuzzers(args) == 0
  if args.command == 'run_fuzzer':
    print('Not implemented')
    return False
  print('Invalid argument option, use build_fuzzers or run_fuzzer.')
  return False


def build_fuzzers(args):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Returns:
    True on success False on failure.
  """

  # TODO: Fix return value bubble to actually handle errors.
  with tempfile.TemporaryDirectory() as tmp_dir:
    inferred_url, repo_name = build_specified_commit.detect_main_repo(
        args.project_name, repo_name=args.repo_name)
    build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                  tmp_dir,
                                                  repo_name=repo_name)
    build_data = build_specified_commit.BuildData()
    build_data.project_name = args.project_name
    build_data.sanitizer = 'address'
    build_data.engine = 'libfuzzer'
    build_data.architecture = 'x86_64'
    return build_specified_commit.build_fuzzers_from_commit(
        args.commit_sha, build_repo_manager, build_data) == 0


if __name__ == '__main__':
  main()
