# Copyright 2019 Google LLC
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
"""Uses bisection to determine which commit a bug was introduced and fixed.
This module takes a high and a low commit SHA, a repo name, and a bug.
The module bisects the high and low commit SHA searching for the location
where the bug was introduced. It also looks for where the bug was fixed.
This is done with the following steps:


  NOTE: NEEDS TO BE RUN FROM THE OSS-Fuzz HOME directory

  Typical usage example:
        python3 infra/bisector.py
          --commit_old 1e403e9259a1abedf108ab86f711ba52c907226d
          --commit_new f79be4f2330f4b89ea2f42e1c44ca998c59a0c0f
          --fuzz_target rules_fuzzer
          --project_name yara
          --testcase infra/yara_testcase
          --sanitizer address
"""

import argparse
from dataclasses import dataclass
import os
import tempfile

import build_specified_commit
import helper
import repo_manager


@dataclass
class BuildData():
  """List of data requried for bisection of errors in OSS-Fuzz projects.

  Attributes:
    project_name: The name of the OSS-Fuzz project that is being checked
    engine: The fuzzing engine to be used
    sanitizer: The sanitizer to be used
    architecture: CPU architecture to build the fuzzer for
  """
  project_name: str
  engine: str
  sanitizer: str
  architecture: str


def main():
  """Finds the commit SHA where an error was initally introduced."""
  oss_fuzz_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
  if os.getcwd() != oss_fuzz_dir:
    print('Changing directory to OSS-Fuzz home directory')
    os.chdir(oss_fuzz_dir)
  parser = argparse.ArgumentParser(
      description='git bisection for finding introduction of bugs')

  parser.add_argument(
      '--project_name',
      help='The name of the project where the bug occured',
      required=True)
  parser.add_argument(
      '--commit_new',
      help='The newest commit SHA to be bisected',
      required=True)
  parser.add_argument(
      '--commit_old',
      help='The oldest commit SHA to be bisected',
      required=True)
  parser.add_argument(
      '--fuzz_target', help='the name of the fuzzer to be built', required=True)
  parser.add_argument('--testcase', help='path to test case', required=True)
  parser.add_argument(
      '--engine', help='the default is "libfuzzer"', default='libfuzzer')
  parser.add_argument(
      '--sanitizer', default='address', help='the default is "address"')
  parser.add_argument('--architecture', default='x86_64')
  args = parser.parse_args()
  build_data = BuildData(args.project_name, args.engine, args.sanitizer,
                         args.architecture)
  error_sha = bisect(args.commit_old, args.commit_new, args.testcase,
                     args.fuzz_target, build_data)
  if not error_sha:
    print('No error was found in commit range %s:%s' %
          (args.commit_old, args.commit_new))
    return 1
  if error_sha == args.commit_old:
    print('Bisection Error: Both the first and the last commits in the given ' +
          'range have the same behavior, bisection is not possible. ')
    return 1
  print('Error was introduced at commit %s' % error_sha)
  return 0


def bisect(commit_old, commit_new, testcase, fuzz_target, build_data):
  """From a commit range, this function caluclates which introduced a
  specific error from a fuzz testcase.

  Args:
    commit_old: The oldest commit in the error regression range
    commit_new: The newest commit in the error regression range
    testcase: The file path of the test case that triggers the error
    fuzz_target: The name of the fuzzer to be tested
    build_data: a class holding all of the input parameters for bisection

  Returns:
    The commit SHA that introduced the error or None

  Raises:
    ValueError: when a repo url can't be determine from the project
  """
  with tempfile.TemporaryDirectory() as tmp_dir:
    repo_url, repo_name = build_specified_commit.detect_main_repo_from_docker(
        build_data.project_name, commit_old)
    if not repo_url or not repo_name:
      raise ValueError('Main git repo can not be determined.')
    bisect_repo_manager = repo_manager.RepoManager(
        repo_url, tmp_dir, repo_name=repo_name)
    commit_list = bisect_repo_manager.get_commit_list(commit_old, commit_new)
    old_idx = len(commit_list) - 1
    new_idx = 0
    build_specified_commit.build_fuzzer_from_commit(
        build_data.project_name, commit_list[new_idx],
        bisect_repo_manager.repo_dir, build_data.engine, build_data.sanitizer,
        build_data.architecture, bisect_repo_manager)
    expected_error_code = helper.reproduce_impl(build_data.project_name,
                                                fuzz_target, False, [], [],
                                                testcase)

    # Check if the error is persistent through the commit range
    build_specified_commit.build_fuzzer_from_commit(
        build_data.project_name, commit_list[old_idx],
        bisect_repo_manager.repo_dir, build_data.engine, build_data.sanitizer,
        build_data.architecture, bisect_repo_manager)
    oldest_error_code = helper.reproduce_impl(build_data.project_name,
                                              fuzz_target, False, [], [],
                                              testcase)

    if expected_error_code == oldest_error_code:
      return commit_list[old_idx]

    while old_idx - new_idx > 1:
      curr_idx = (old_idx + new_idx) // 2
      build_specified_commit.build_fuzzer_from_commit(
          build_data.project_name, commit_list[curr_idx],
          bisect_repo_manager.repo_dir, build_data.engine, build_data.sanitizer,
          build_data.architecture, bisect_repo_manager)
      error_code = helper.reproduce_impl(build_data.project_name, fuzz_target,
                                         False, [], [], testcase)
      if expected_error_code == error_code:
        new_idx = curr_idx
      else:
        old_idx = curr_idx
    return commit_list[new_idx]


if __name__ == '__main__':
  main()
