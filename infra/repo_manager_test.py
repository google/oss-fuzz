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
"""Test the functionality of the RepoManager class."""

import contextlib
import os
import tempfile
import unittest
from unittest import mock

import repo_manager
import utils

# pylint: disable=protected-access

OSS_FUZZ_REPO_URL = 'https://github.com/google/oss-fuzz'


@contextlib.contextmanager
def get_oss_fuzz_repo():
  """Clones a temporary copy of the OSS-Fuzz repo. Returns the path to the
  repo."""
  repo_name = 'oss-fuzz'
  with tempfile.TemporaryDirectory() as tmp_dir:
    repo_manager._clone(OSS_FUZZ_REPO_URL, tmp_dir, repo_name)
    yield os.path.join(tmp_dir, repo_name)


class CloneTest(unittest.TestCase):
  """Tests the _clone function."""

  @unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                   'INTEGRATION_TESTS=1 not set')
  def test_clone_valid_repo_integration(self):
    """Integration test that tests the correct location of the git repo."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      git_path = os.path.join(oss_fuzz_repo, '.git')
      self.assertTrue(os.path.isdir(git_path))

  def test_clone_invalid_repo(self):
    """Tests that cloning an invalid repo will fail."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with self.assertRaises(RuntimeError):
        repo_manager._clone('https://github.com/oss-fuzz-not-real.git', tmp_dir,
                            'oss-fuzz')

  @mock.patch('utils.execute')
  def test_clone_with_username(self, mock_execute):  # pylint: disable=no-self-use
    """Test clone with username."""
    repo_manager._clone('https://github.com/fake/repo.git',
                        '/',
                        'name',
                        username='user',
                        password='password')
    mock_execute.assert_called_once_with([
        'git', 'clone', 'https://user:password@github.com/fake/repo.git', 'name'
    ],
                                         location='/',
                                         check_result=True,
                                         log_command=False)


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class RepoManagerCheckoutTest(unittest.TestCase):
  """Tests the checkout functionality of RepoManager."""

  def test_checkout_valid_commit(self):
    """Tests that the git checkout command works."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      commit_to_test = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      repo_man.checkout_commit(commit_to_test)
      self.assertEqual(commit_to_test, repo_man.get_current_commit())

  def test_checkout_invalid_commit(self):
    """Tests that the git checkout invalid commit fails."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      with self.assertRaises(ValueError):
        repo_man.checkout_commit(' ')
      with self.assertRaises(ValueError):
        repo_man.checkout_commit('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
      with self.assertRaises(ValueError):
        repo_man.checkout_commit('not-a-valid-commit')


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class RepoManagerGetCommitListTest(unittest.TestCase):
  """Tests the get_commit_list method of RepoManager."""

  def test_get_valid_commit_list(self):
    """Tests an accurate commit list can be retrieved from the repo manager."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      old_commit = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      new_commit = 'fa662173bfeb3ba08d2e84cefc363be11e6c8463'
      commit_list = [
          'fa662173bfeb3ba08d2e84cefc363be11e6c8463',
          '17035317a44fa89d22fe6846d868d4bf57def78b',
          '97dee00a3c4ce95071c3e061592f5fd577dea886',
          '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      ]
      result_list = repo_man.get_commit_list(new_commit, old_commit)
      self.assertListEqual(commit_list, result_list)

  def test_get_invalid_commit_list(self):
    """Tests that the proper errors are thrown when invalid commits are
    passed to get_commit_list."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      old_commit = '04ea24ee15bbe46a19e5da6c5f022a2ffdfbdb3b'
      new_commit = 'fa662173bfeb3ba08d2e84cefc363be11e6c8463'
      with self.assertRaises(ValueError):
        repo_man.get_commit_list('fakecommit', new_commit)
      with self.assertRaises(ValueError):
        repo_man.get_commit_list(new_commit, 'fakecommit')
      with self.assertRaises(RuntimeError):
        repo_man.get_commit_list(old_commit, new_commit)  # pylint: disable=arguments-out-of-order


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class GitDiffTest(unittest.TestCase):
  """Tests get_git_diff."""

  def test_diff_exists(self):
    """Tests that a real diff is returned when a valid repo manager exists."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      with mock.patch.object(utils,
                             'execute',
                             return_value=('test.py\ndiff.py', None, 0)):
        diff = repo_man.get_git_diff()
        self.assertCountEqual(diff, ['test.py', 'diff.py'])

  def test_diff_empty(self):
    """Tests that None is returned when there is no difference between repos."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      with mock.patch.object(utils, 'execute', return_value=('', None, 0)):
        diff = repo_man.get_git_diff()
        self.assertIsNone(diff)

  def test_error_on_command(self):
    """Tests that None is returned when the command errors out."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      with mock.patch.object(utils,
                             'execute',
                             return_value=('', 'Test error.', 1)):
        diff = repo_man.get_git_diff()
        self.assertIsNone(diff)

  def test_diff_no_change(self):
    """Tests that None is returned when there is no difference between repos."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      diff = repo_man.get_git_diff()
      self.assertIsNone(diff)


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class CheckoutPrIntegrationTest(unittest.TestCase):
  """Does Integration tests on the checkout_pr method of RepoManager."""

  def test_pull_request_exists(self):
    """Tests that a diff is returned when a valid PR is checked out."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      repo_man.checkout_pr('refs/pull/3415/merge')
      diff = repo_man.get_git_diff()
      self.assertCountEqual(diff, ['README.md'])

  def test_checkout_invalid_pull_request(self):
    """Tests that the git checkout invalid pull request fails."""
    with get_oss_fuzz_repo() as oss_fuzz_repo:
      repo_man = repo_manager.RepoManager(oss_fuzz_repo)
      with self.assertRaises(RuntimeError):
        repo_man.checkout_pr(' ')
      with self.assertRaises(RuntimeError):
        repo_man.checkout_pr('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
      with self.assertRaises(RuntimeError):
        repo_man.checkout_pr('not/a/valid/pr')


if __name__ == '__main__':
  unittest.main()
