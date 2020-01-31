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
"""Test the functionality of the RepoManager class."""

import os
import unittest
import tempfile

import repo_manager

OSS_FUZZ_REPO = 'https://github.com/google/oss-fuzz'


class TestRepoManager(unittest.TestCase):
  """Class to test the functionality of the RepoManager class."""


class RepoManagerCloneUnitTests(unittest.TestCase):
  """Class to test the functionality of clone of the RepoManager class."""

  def test_clone_valid_repo(self):
    """Tests the correct location of the git repo."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      git_path = os.path.join(test_repo_manager.base_dir,
                              test_repo_manager.repo_name, '.git')
      self.assertTrue(os.path.isdir(git_path))
      test_repo_manager.remove_repo()

  def test_clone_invalid_repo(self):
    """Test that constructing RepoManager with an invalid repo will fail."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with self.assertRaises(ValueError):
        repo_manager.RepoManager(' ', tmp_dir)
      with self.assertRaises(ValueError):
        repo_manager.RepoManager('not_a_valid_repo', tmp_dir)
      with self.assertRaises(ValueError):
        repo_manager.RepoManager('https://github.com/oss-fuzz-not-real.git',
                                 tmp_dir)


class RepoManagerCheckoutUnitTests(unittest.TestCase):
  """Class to test the functionality of checkout of the RepoManager class."""

  def test_checkout_valid_commit(self):
    """Tests that the git checkout command works."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      commit_to_test = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      test_repo_manager.checkout_commit(commit_to_test)
      self.assertEqual(commit_to_test, test_repo_manager.get_current_commit())

  def test_checkout_invalid_commit(self):
    """Tests that the git checkout invalid commit fails."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      with self.assertRaises(ValueError):
        test_repo_manager.checkout_commit(' ')
      with self.assertRaises(ValueError):
        test_repo_manager.checkout_commit(
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
      with self.assertRaises(ValueError):
        test_repo_manager.checkout_commit('not-a-valid-commit')


class RepoManagerGetCommitListUnitTests(unittest.TestCase):
  """Class to test the functionality of get commit list in the
   RepoManager class."""

  def test_get_valid_commit_list(self):
    """Tests an accurate commit list can be retrieved from the repo manager."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      old_commit = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      new_commit = 'fa662173bfeb3ba08d2e84cefc363be11e6c8463'
      commit_list = [
          'fa662173bfeb3ba08d2e84cefc363be11e6c8463',
          '17035317a44fa89d22fe6846d868d4bf57def78b',
          '97dee00a3c4ce95071c3e061592f5fd577dea886',
          '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      ]
      result_list = test_repo_manager.get_commit_list(old_commit, new_commit)
      self.assertListEqual(commit_list, result_list)

  def test_invalid_commit_list(self):
    """Tests that the propper Errors are thrown when invalid commits are
    passed."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      old_commit = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      new_commit = 'fa662173bfeb3ba08d2e84cefc363be11e6c8463'
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      with self.assertRaises(ValueError):
        test_repo_manager.get_commit_list('fakecommit', new_commit)
      with self.assertRaises(ValueError):
        test_repo_manager.get_commit_list(new_commit, 'fakecommit')
      with self.assertRaises(RuntimeError):
        # pylint: disable=arguments-out-of-order
        test_repo_manager.get_commit_list(new_commit, old_commit)


class RepoManagerCheckoutPullRequestUnitTests(unittest.TestCase):
  """Class to test the functionality of checkout_pr of the RepoManager class."""

  def test_checkout_valid_pull_request(self):
    """Tests that the git checkout pull request works."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      test_repo_manager.checkout_pr('refs/pull/3310/merge')
      self.assertEqual(test_repo_manager.get_current_commit(),
                       'ff00c1685ccf32f729cf6c834e641223ce6262e4')

  def test_checkout_invalid_pull_request(self):
    """Tests that the git checkout invalid pull request fails."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo_manager = repo_manager.RepoManager(OSS_FUZZ_REPO, tmp_dir)
      with self.assertRaises(RuntimeError):
        test_repo_manager.checkout_pr(' ')
      with self.assertRaises(RuntimeError):
        test_repo_manager.checkout_pr(
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
      with self.assertRaises(RuntimeError):
        test_repo_manager.checkout_pr('not/a/valid/pr')


if __name__ == '__main__':
  unittest.main()
