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
"""Test the functionality of bisection module:
1) Test a known case where an error appears in a regression range.
2) Bisect can handle incorrect inputs.

IMPORTANT: This test needs to be run with root privileges.
"""

import os
import unittest

import bisector
import build_specified_commit
import test_repos

# Necessary because __file__ changes with os.chdir
TEST_DIR_PATH = os.path.dirname(os.path.realpath(__file__))


@unittest.skip('Test is too long to be run with presubmit.')
class BisectIntegrationTests(unittest.TestCase):
  """Class to test the functionality of bisection method."""

  BISECT_TYPE = 'regressed'

  def test_bisect_invalid_repo(self):
    """Test the bisection method on a project that does not exist."""
    test_repo = test_repos.INVALID_REPO
    build_data = build_specified_commit.BuildData(
        project_name=test_repo.project_name,
        engine='libfuzzer',
        sanitizer='address',
        architecture='x86_64')
    with self.assertRaises(ValueError):
      bisector.bisect(self.BISECT_TYPE, test_repo.old_commit,
                      test_repo.new_commit, test_repo.testcase_path,
                      test_repo.fuzz_target, build_data)

  def test_bisect(self):
    """Test the bisect method on example projects."""
    for test_repo in test_repos.TEST_REPOS:
      if test_repo.new_commit:
        build_data = build_specified_commit.BuildData(
            project_name=test_repo.project_name,
            engine='libfuzzer',
            sanitizer='address',
            architecture='x86_64')
        result = bisector.bisect(self.BISECT_TYPE, test_repo.old_commit,
                                 test_repo.new_commit, test_repo.testcase_path,
                                 test_repo.fuzz_target, build_data)
        self.assertEqual(result.commit, test_repo.intro_commit)


if __name__ == '__main__':
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != os.path.dirname(TEST_DIR_PATH):
    os.chdir(os.path.dirname(TEST_DIR_PATH))
  unittest.main()
