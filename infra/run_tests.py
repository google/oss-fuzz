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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.
"""Runs the tests associated with the changes made to the repo."""
import os
import sys

import utils

# A list of tests that should not be run due to run time.
BLACK_LIST = ['bisector_test.py']


def run_tests():
  """Run python tests that were affected by a change.."""
  passing_tests = []
  failing_tests = []
  changed_dirs = get_changed_dirs()
  for directory in changed_dirs:
    passing, failing = run_test_in_dir(directory)
    passing_tests.extend(passing)
    failing_tests.extend(failing)
  print('The following tests have passed:', ' '.join(passing_tests))
  if failing_tests:
    print('The following tests have failed:', ' '.join(failing_tests))
    return 1
  print('All tests have passed.')
  return 0


def run_test(file_path):
  """Run a specific python tests.

  Args:
    file_path: The file path of the python test test to run.

  Returns:
    True on passing or False on failing.
  """
  print('Running test:', file_path)
  stdout, stderr, err_code = utils.execute(['sudo', 'python3', file_path])
  print('Test stdout:', stdout)
  print('Test stderr:', stderr)
  return err_code == 0


def run_test_in_dir(dir_to_run):
  """Runs all the tests in a specific directory.

  Args:
    dir_to_run: The location to look for tests.

  Returns:
    (list of passing tests, list of failing tests)
  """
  passing = []
  failing = []
  print('Running tests in directory: ', dir_to_run)
  for file_name in os.listdir(dir_to_run):
    if '_test.py' in file_name:
      if file_name in BLACK_LIST:
        continue
      if run_test(os.path.join(dir_to_run, file_name)):
        passing.append(file_name)
      else:
        failing.append(file_name)
  return passing, failing


def get_changed_dirs():
  """Finds changed directories in the current branch.

  Returns:
    The list of directories that are affected by the change.
  """
  change_files, _, _ = utils.execute(
      ['git', 'diff', '--name-only', 'origin/master'])
  change_files = change_files.split('\n')
  change_dirs = []
  for file_path in change_files:
    dir_name = os.path.dirname(file_path)
    if dir_name and dir_name not in change_dirs:
      change_dirs.append(dir_name)
  return change_dirs


if __name__ == '__main__':
  sys.exit(run_tests())
