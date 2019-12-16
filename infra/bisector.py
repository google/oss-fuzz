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
"""Uses _bisection to determine which commit a bug was introduced and fixed.
This module takes a high and a low commit SHA, a repo name, and a bug.
The module bisects the high and low commit SHA searching for the location
where the bug was introduced. It also looks for where the bug was fixed.
This is done with the following steps:


  NOTE: NEEDS TO BE RUN FROM THE oss-fuzz HOME directory

  Typical usage example:
        python3 infra/bisector.py
          --commit_old 1e403e9259a1abedf108ab86f711ba52c907226d
          --commit_new f79be4f2330f4b89ea2f42e1c44ca998c59a0c0f
          --fuzz_target rules_fuzzer
          --project_name yara
          --test_case infra/yara_test_case
          --sanitizer address
"""

import argparse
import os

from build_specified_commit import build_fuzzer_from_commit
from build_specified_commit import infer_main_repo
from helper import reproduce_impl
from repo_manager import RepoManager


def main():
  """Finds the commit SHA where an error was initally introduced."""
  parser = argparse.ArgumentParser(
      'bisector.py',
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
  parser.add_argument(
      '--test_case', help='the test_case to be reproduced', required=True)
  parser.add_argument('--engine', default='libfuzzer')
  parser.add_argument(
      '--sanitizer',
      default='address',
      help='the default is "address"')
  parser.add_argument('--architecture', default='x86_64')
  args = parser.parse_args()

  if not os.getcwd().endswith('oss-fuzz'):
    print("Error: bisector.py needs to be run from the oss-fuzz home directory")
    return 1

  error_sha = bisect(args.project_name, args.commit_old,
                             args.commit_new, args.engine, args.sanitizer,
                             args.architecture, args.test_case,
                             args.fuzz_target)
  if not error_sha:
    print('No error was found in commit range %s:%s' %
          (args.commit_old, args.commit_new))
  else:
    print('Error was introduced at commit %s' % error_sha)


def bisect(project_name, commit_old, commit_new, engine, sanitizer,
                   architecture, test_case, fuzz_target):
  """Creates an bisection call that kicks off the error detection.

  This function is necessary in order to get the error code of the newest commit. This
  sets a standard for what the error actually is.

  Args:
    project_name: The name of the oss fuzz project that is being checked
    commit_old: The oldest commit in the error regression range
    commit_new: The newest commit in the error regression range
    engine: The fuzzing engine to be used
    sanitizer: The fuzzing sanitizer to be used
    architecture: The system architecture being fuzzed
    test_case: The file path of the test case that triggers the error
    fuzz_target: The name of the fuzzer to be tested

  Returns:
    The commit SHA that introduced the error or None
  """
  local_store_path = 'tmp'
  repo_url = infer_main_repo(project_name, local_store_path, commit_old)
  repo_manager = RepoManager(repo_url, local_store_path)
  commit_list = repo_manager.get_commit_list(commit_old, commit_new)
  build_fuzzer_from_commit(project_name, commit_list[0], repo_manager.repo_dir,
                           engine, sanitizer, architecture, repo_manager)
  error_code = reproduce_impl(project_name, fuzz_target, False, [], [],
                              test_case)
  old_idx = len(commit_list) - 1
  new_idx = 0
  if len(commit_list) == 1:
    if not error_code:
      return None
    return commit_list[0]

  while old_idx - new_idx != 1:
    cur_idx = (old_idx + new_idx) //2
    build_fuzzer_from_commit(project_name, commit_list[cur_idx],
                           repo_manager.repo_dir, engine, sanitizer,
                           architecture, repo_manager)
    error_exists = (
        reproduce_impl(project_name, fuzz_target, False, [], [],
                      test_case) == error_code)
    if error_exists == error_code:
      new_idx = cur_idx
    else:
      old_idx  = cur_idx
  return commit_list[new_idx]


if __name__ == '__main__':
  main()
