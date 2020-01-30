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


  NOTE: Needs to be run from root of the OSS-Fuzz source checkout.

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
import logging
import tempfile

import build_specified_commit
import helper
import repo_manager
import utils


def main():
  """Finds the commit SHA where an error was initally introduced."""
  utils.chdir_to_root()
  parser = argparse.ArgumentParser(
      description='git bisection for finding introduction of bugs')

  parser.add_argument('--project_name',
                      help='The name of the project where the bug occurred.',
                      required=True)
  parser.add_argument('--new_commit',
                      help='The newest commit SHA to be bisected.',
                      required=True)
  parser.add_argument('--old_commit',
                      help='The oldest commit SHA to be bisected.',
                      required=True)
  parser.add_argument('--fuzz_target',
                      help='The name of the fuzzer to be built.',
                      required=True)
  parser.add_argument('--test_case_path',
                      help='The path to test case.',
                      required=True)
  parser.add_argument('--engine',
                      help='The default is "libfuzzer".',
                      default='libfuzzer')
  parser.add_argument('--sanitizer',
                      default='address',
                      help='The default is "address".')
  parser.add_argument('--architecture', default='x86_64')
  args = parser.parse_args()

  build_data = build_specified_commit.BuildData(project_name=args.project_name,
                                                engine=args.engine,
                                                sanitizer=args.sanitizer,
                                                architecture=args.architecture)

  error_sha = bisect(args.old_commit, args.new_commit, args.test_case_path,
                     args.fuzz_target, build_data)
  if not error_sha:
    logging.error('No error was found in commit range %s:%s', args.commit_old,
                  args.commit_new)
    return 1
  if error_sha == args.commit_old:
    logging.error(
        'Bisection Error: Both the first and the last commits in'
        'the given range have the same behavior, bisection is not possible. ')
    return 1
  print('Error was introduced at commit %s' % error_sha)
  return 0


def bisect(old_commit, new_commit, test_case_path, fuzz_target, build_data):
  """From a commit range, this function caluclates which introduced a
  specific error from a fuzz test_case_path.

  Args:
    old_commit: The oldest commit in the error regression range.
    new_commit: The newest commit in the error regression range.
    test_case_path: The file path of the test case that triggers the error
    fuzz_target: The name of the fuzzer to be tested.
    build_data: a class holding all of the input parameters for bisection.

  Returns:
    The commit SHA that introduced the error or None.

  Raises:
    ValueError: when a repo url can't be determine from the project.
  """
  with tempfile.TemporaryDirectory() as tmp_dir:
    repo_url, repo_name = build_specified_commit.detect_main_repo(
        build_data.project_name, commit=old_commit)
    if not repo_url or not repo_name:
      raise ValueError('Main git repo can not be determined.')
    bisect_repo_manager = repo_manager.RepoManager(repo_url,
                                                   tmp_dir,
                                                   repo_name=repo_name)
    commit_list = bisect_repo_manager.get_commit_list(old_commit, new_commit)
    old_idx = len(commit_list) - 1
    new_idx = 0
    build_specified_commit.build_fuzzers_from_commit(commit_list[new_idx],
                                                     bisect_repo_manager,
                                                     build_data)
    expected_error_code = helper.reproduce_impl(build_data.project_name,
                                                fuzz_target, False, [], [],
                                                test_case_path)

    # Check if the error is persistent through the commit range
    build_specified_commit.build_fuzzers_from_commit(
        commit_list[old_idx],
        bisect_repo_manager,
        build_data,
    )

    if expected_error_code == helper.reproduce_impl(build_data.project_name,
                                                    fuzz_target, False, [], [],
                                                    test_case_path):
      return commit_list[old_idx]

    while old_idx - new_idx > 1:
      curr_idx = (old_idx + new_idx) // 2
      build_specified_commit.build_fuzzers_from_commit(commit_list[curr_idx],
                                                       bisect_repo_manager,
                                                       build_data)
      error_code = helper.reproduce_impl(build_data.project_name, fuzz_target,
                                         False, [], [], test_case_path)
      if expected_error_code == error_code:
        new_idx = curr_idx
      else:
        old_idx = curr_idx
    return commit_list[new_idx]


if __name__ == '__main__':
  main()
