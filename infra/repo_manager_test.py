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
"""Test the functionality of the RepoManager class
The will consist of the following functional tests
  1. Cloning of directory in desired location
  2. Checking out a specific commit
"""

import unittest
from RepoManager import RepoManager
import os

class TestRepoManager(unittest.TestCase):
  """Class to test the functionality of the RepoManager class."""

  rm = None
  test_repo = 'https://github.com/curl/curl'

  def setUp(self):
    """Sets up the test enviroment by creating a sample RM instance."""
    self.rm = RepoManager(self.test_repo, local_dir='tmp')

  def tearDown(self):
    """Removes and cleans up the RM instance."""
    self.rm.remove_repo()

  def test_clone_correctly(self):
    """Tests the correct location of the git repo."""
    git_path = os.path.join(self.rm.local_dir, self.rm.repo_name, '.git')
    self.assertTrue(os.path.isdir(git_path))

  def test_checkout_commit(self):
    """Tests that the git checkout command works."""
    commit_to_test = '036ebac0134de3b72052a46f734e4ca81bb96055'
    self.rm.checkout_commit(commit_to_test)
    self.assertEqual(commit_to_test, self.rm.get_current_SHA())
    self.assertEqual(self.rm.checkout_commit('sdfasdf'), 1)


if __name__ == '__main__':
  unittest.main()
