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
  3. Can get a list of commits between two SHAs
"""

from RepoManager import RepoManager
from RepoManager import RepoManagerError
import os
import unittest


class TestRepoManager(unittest.TestCase):
  """Class to test the functionality of the RepoManager class."""

  curl_repo = 'https://github.com/curl/curl'

  def test_clone_correctly(self):
    """Tests the correct location of the git repo."""
    rm = RepoManager(self.curl_repo, base_dir='tmp')
    git_path = os.path.join(rm.base_dir, rm.repo_name, '.git')
    self.assertTrue(os.path.isdir(git_path))
    rm.remove_repo()
    with self.assertRaises(RepoManagerError):
      rm = RepoManager(' ')

  def test_checkout_commit(self):
    """Tests that the git checkout command works."""
    rm = RepoManager(self.curl_repo, base_dir='tmp')
    commit_to_test = '036ebac0134de3b72052a46f734e4ca81bb96055'
    rm.checkout_commit(commit_to_test)
    self.assertEqual(commit_to_test, rm.get_current_commit())
    with self.assertRaises(RepoManagerError):
      rm.checkout_commit(' ')
    with self.assertRaises(RepoManagerError):
      rm.checkout_commit('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    rm.remove_repo()

  def test_get_commit_list(self):
    """Tests an accurate commit list can be retrived from the repo manager."""
    rm = RepoManager(self.curl_repo, base_dir='tmp')
    old_commit = '7cf18b05e04bbb0f08c74d2567b0648f6c31a952'
    new_commit = '113db127ee2b2f874dfcce406103ffe666e11953'
    commit_list = [
        '113db127ee2b2f874dfcce406103ffe666e11953',
        '793e37767581aec7102d2ecafa34fc1316b1b31f',
        '9a2cbf30b81a2b57149bb20e78e2e4cb5c2ff389',
        '7cf18b05e04bbb0f08c74d2567b0648f6c31a952'
    ]
    result_list = rm.get_commit_list(old_commit, new_commit)
    self.assertListEqual(commit_list, result_list)
    with self.assertRaises(RepoManagerError):
      rm.get_commit_list('asafd', new_commit)
    with self.assertRaises(RepoManagerError):
      rm.get_commit_list(new_commit, 'asdfasdf')
    with self.assertRaises(RepoManagerError):
      result_list = rm.get_commit_list(new_commit, old_commit)


if __name__ == '__main__':
  unittest.main()
