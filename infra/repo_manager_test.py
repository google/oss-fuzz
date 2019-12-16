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
"""Test the functionality of the RepoManager class
The will consist of the following functional tests
  1. Cloning of directory in desired location
  2. Checking out a specific commit
  3. Can get a list of commits between two SHAs
"""

import os
import tempfile
import unittest
import shutil

from RepoManager import RepoManager
from RepoManager import RepoManagerError


class TestRepoManager(unittest.TestCase):
  """Class to test the functionality of the RepoManager class."""

  curl_repo = 'https://github.com/curl/curl'

  def test_clone_correctly(self):
    """Tests the correct location of the git repo."""
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    git_path = os.path.join(repo_manager.base_dir, repo_manager.repo_name,
                            '.git')
    self.assertTrue(os.path.isdir(git_path))
    repo_manager.remove_repo()
    with self.assertRaises(RepoManagerError):
      repo_manager = RepoManager(' ', tmp_dir)

  def test_checkout_commit(self):
    """Tests that the git checkout command works."""
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    commit_to_test = '036ebac0134de3b72052a46f734e4ca81bb96055'
    repo_manager.checkout_commit(commit_to_test)
    self.assertEqual(commit_to_test, repo_manager.get_current_commit())
    with self.assertRaises(ValueError):
      repo_manager.checkout_commit(' ')
    with self.assertRaises(RepoManagerError):
      repo_manager.checkout_commit('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    repo_manager.remove_repo()

  def test_get_commit_list(self):
    """Tests an accurate commit list can be retrived from the repo manager."""
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    old_commit = '7cf18b05e04bbb0f08c74d2567b0648f6c31a952'
    new_commit = '113db127ee2b2f874dfcce406103ffe666e11953'
    commit_list = [
        '113db127ee2b2f874dfcce406103ffe666e11953',
        '793e37767581aec7102d2ecafa34fc1316b1b31f',
        '9a2cbf30b81a2b57149bb20e78e2e4cb5c2ff389',
        '7cf18b05e04bbb0f08c74d2567b0648f6c31a952'
    ]
    result_list = repo_manager.get_commit_list(old_commit, new_commit)
    self.assertListEqual(commit_list, result_list)
    with self.assertRaises(RepoManagerError):
      repo_manager.get_commit_list('asafd', new_commit)
    with self.assertRaises(RepoManagerError):
      repo_manager.get_commit_list(new_commit, 'asdfasdf')
    with self.assertRaises(RepoManagerError):
      # Testing commits out of order
      result_list = repo_manager.get_commit_list(new_commit, old_commit)

  def test_get_remote_branch_path(self):
    """Tests that repo manager can check if a branch exists remotely."""
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    self.assertEqual(repo_manager.get_remote_branch_path('wolfssl-crl'), 'origin/bagder/wolfssl-crl')
    with self.assertRaises(ValueError):
      repo_manager.branch_path(' ')
    self.assertIsNone(repo_manager.get_remote_branch_path('aaaaaaaaaaaaaaaa'))

    # Note: looking at stale branch of curl repo, test could fail in future
    self.assertEqual(repo_manager.branch_path('ci'),'origin/dfandrich/ci')

  def test_get_current_branch(self):
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    self.assertEqual('master', repo_manager.get_current_branch())

  def test_checkout_branch(self):
    repo_manager = RepoManager(self.curl_repo, tmp_dir)
    repo_manager.checkout_branch('wolfssl-crl')
    self.assertEqual(repo_manager.get_current_branch(), 'bagder/wolfssl-crl')
    with self.assertRaises(RepoManagerError):
      repo_manager.checkout_branch('aaaaaaaaa')

  def test_checkout_pull_request(self):
    repo_manager = RepoManager(self.curl_repo, tmp_dir)

    # Note: This test may fail because the curl pull request might have closed
    repo_manager.checkout_pull_request(2682)
    self.assertEqual(repo_manager.get_current_branch(), '2682-branch')
    with self.assertRaises(RepoManagerError):
      repo_manager.checkout_pull_request(10000000)




if __name__ == '__main__':
  tmp_dir = tempfile.mkdtemp()
  unittest.main()
  shutil.rmtree(tmp_dir)
