# Copyright 2021 Google LLC
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
"""Tests for git."""
import filecmp
import functools
import os
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
sys.path.append(INFRA_DIR)

from filestore import git
import test_helpers

# pylint: disable=protected-access,no-self-use


class GitCredentialsTest(unittest.TestCase):
  """Tests GitHub storage credentials with Git's credential protocol."""

  def get_credentials(self,
                      repo_url,
                      credential_url,
                      token='test-token',
                      server_url='https://github.com',
                      repository='owner/storage'):
    """Returns credentials resolved by Git for a URL."""
    fallback = '!f() { echo username=existing; echo password=existing; }; f'
    env = {
        'GITHUB_TOKEN': token,
        'GITHUB_SERVER_URL': server_url,
        'GITHUB_REPOSITORY': repository,
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_TERMINAL_PROMPT': '0',
        'GIT_CONFIG_COUNT': '1',
        'GIT_CONFIG_KEY_0': 'credential.helper',
        'GIT_CONFIG_VALUE_0': fallback,
    }
    fill = functools.partial(subprocess.check_output,
                             input=f'url={credential_url}\n\n'.encode(),
                             timeout=10)

    with tempfile.TemporaryDirectory() as directory:
      with mock.patch.dict(os.environ, env):
        with mock.patch.object(git.subprocess, 'check_call', side_effect=fill):
          credentials = git.git_runner(directory, repo_url)('credential',
                                                            'fill')
    return credentials.decode()

  def test_github_credentials(self):
    """Uses the action token for GitHub and configured Enterprise storage."""
    for host in ('github.com', 'github.example'):
      with self.subTest(host=host):
        url = f'https://{host}/owner/storage.git'
        credentials = self.get_credentials(url,
                                           url,
                                           server_url=f'https://{host}')
        self.assertIn('username=x-access-token\n', credentials)
        self.assertIn('password=test-token\n', credentials)

  def test_different_repo(self):
    """GITHUB_TOKEN isn't authorized for another repo on the same host."""
    url = 'https://github.com/owner/storage.git'
    credentials = self.get_credentials(url, url, repository='owner/other')
    self.assertIn('username=existing\n', credentials)
    self.assertIn('password=existing\n', credentials)

  def test_preserves_other_credentials(self):
    """Leaves unrelated hosts and explicit credentials to existing helpers."""
    for repo_url, credential_url, token in [
        ('https://github.com/owner/storage.git',
         'https://other.example/owner/storage.git', 'test-token'),
        ('https://other.example/owner/storage.git',
         'https://other.example/owner/storage.git', 'test-token'),
        ('http://github.com/owner/storage.git',
         'http://github.com/owner/storage.git', 'test-token'),
        ('git@github.com:owner/storage.git',
         'https://github.com/owner/storage.git', 'test-token'),
        ('https://user@github.com/owner/storage.git',
         'https://github.com/owner/storage.git', 'test-token'),
        ('https://github.com/owner/storage.git',
         'https://github.com/owner/storage.git', ''),
    ]:
      with self.subTest(repo_url=repo_url,
                        credential_url=credential_url,
                        token=token):
        credentials = self.get_credentials(repo_url, credential_url, token)
        self.assertIn('username=existing\n', credentials)
        self.assertIn('password=existing\n', credentials)


class GitFilestoreTest(unittest.TestCase):
  """Tests for GitFilestore."""

  def setUp(self):
    self.git_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.git_dir.cleanup)

    self.local_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.local_dir.cleanup)

    self.download_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.download_dir.cleanup)

    with open(os.path.join(self.local_dir.name, 'a'), 'w') as handle:
      handle.write('')

    os.makedirs(os.path.join(self.local_dir.name, 'b'))

    with open(os.path.join(self.local_dir.name, 'b', 'c'), 'w') as handle:
      handle.write('')

    self.git_repo = git.git_runner(self.git_dir.name)
    self.git_repo('init', '--bare')

    self.config = test_helpers.create_run_config(
        git_store_repo='file://' + self.git_dir.name,
        git_store_branch='main',
        git_store_branch_coverage='cov-branch')

    self.mock_ci_filestore = mock.MagicMock()
    self.git_store = git.GitFilestore(self.config, self.mock_ci_filestore)

  def assert_dirs_same(self, first, second):
    """Asserts two dirs are the same."""
    dcmp = filecmp.dircmp(first, second)
    if dcmp.diff_files or dcmp.left_only or dcmp.right_only:
      return False

    return all(
        self.assert_dirs_same(os.path.join(first, subdir),
                              os.path.join(second, subdir))
        for subdir in dcmp.common_dirs)

  def get_repo_filelist(self, branch):
    """Get files in repo."""
    return subprocess.check_output([
        'git', '-C', self.git_dir.name, 'ls-tree', '-r', '--name-only', branch
    ]).decode().splitlines()

  def test_upload_download_corpus(self):
    """Tests uploading and downloading corpus."""
    self.git_store.upload_corpus('target', self.local_dir.name)
    self.git_store.download_corpus('target', self.download_dir.name)
    self.assert_dirs_same(self.local_dir.name, self.download_dir.name)

    self.assertCountEqual([
        'corpus/target/a',
        'corpus/target/b/c',
    ], self.get_repo_filelist('main'))

  def test_upload_download_coverage(self):
    """Tests uploading and downloading corpus."""
    self.git_store.upload_coverage('latest', self.local_dir.name)
    self.git_store.download_coverage('latest', self.download_dir.name)
    self.assert_dirs_same(self.local_dir.name, self.download_dir.name)

    self.assertCountEqual([
        'coverage/latest/a',
        'coverage/latest/b/c',
    ], self.get_repo_filelist('cov-branch'))

  def test_upload_crashes(self):
    """Tests uploading crashes."""
    self.git_store.upload_crashes('current', self.local_dir.name)
    self.mock_ci_filestore.upload_crashes.assert_called_with(
        'current', self.local_dir.name)

  def test_upload_build(self):
    """Tests uploading build."""
    self.git_store.upload_build('sanitizer', self.local_dir.name)
    self.mock_ci_filestore.upload_build.assert_called_with(
        'sanitizer', self.local_dir.name)

  def test_download_build(self):
    """Tests downloading build."""
    self.git_store.download_build('sanitizer', self.download_dir.name)
    self.mock_ci_filestore.download_build.assert_called_with(
        'sanitizer', self.download_dir.name)
