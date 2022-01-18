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
"""Module for a git based filestore."""

import logging
import os
import shutil
import subprocess
import sys
import tempfile

import filestore

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
sys.path.append(INFRA_DIR)

import retry

_PUSH_RETRIES = 3
_PUSH_BACKOFF = 1
_GIT_EMAIL = 'cifuzz@clusterfuzz.com'
_GIT_NAME = 'CIFuzz'
_CORPUS_DIR = 'corpus'
_COVERAGE_DIR = 'coverage'


def git_runner(repo_path):
  """Returns a gits runner for the repo_path."""

  def func(*args):
    return subprocess.check_call(('git', '-C', repo_path) + args)

  return func


# pylint: disable=unused-argument,no-self-use
class GitFilestore(filestore.BaseFilestore):
  """Generic git filestore. This still relies on another filestore provided by
  the CI for larger artifacts or artifacts which make sense to be included as
  the result of a workflow run."""

  def __init__(self, config, ci_filestore):
    super().__init__(config)
    self.repo_path = tempfile.mkdtemp()
    self._git = git_runner(self.repo_path)
    self._clone(self.config.git_store_repo)

    self._ci_filestore = ci_filestore

  def __del__(self):
    shutil.rmtree(self.repo_path)

  def _clone(self, repo_url):
    """Clones repo URL."""
    self._git('clone', repo_url, '.')
    self._git('config', '--local', 'user.email', _GIT_EMAIL)
    self._git('config', '--local', 'user.name', _GIT_NAME)

  def _reset_git(self, branch):
    """Resets the git repo."""
    self._git('fetch', 'origin')
    try:
      self._git('checkout', '-B', branch, 'origin/' + branch)
      self._git('reset', '--hard', 'HEAD')
    except subprocess.CalledProcessError:
      self._git('checkout', '--orphan', branch)

    self._git('clean', '-fxd')

  # pylint: disable=too-many-arguments
  @retry.wrap(_PUSH_RETRIES, _PUSH_BACKOFF)
  def _upload_to_git(self,
                     message,
                     branch,
                     upload_path,
                     local_path,
                     replace=False):
    """Uploads a directory to git. If `replace` is True, then existing contents
    in the upload_path is deleted."""
    self._reset_git(branch)

    full_repo_path = os.path.join(self.repo_path, upload_path)
    if replace and os.path.exists(full_repo_path):
      shutil.rmtree(full_repo_path)

    shutil.copytree(local_path, full_repo_path, dirs_exist_ok=True)
    self._git('add', '.')
    try:
      self._git('commit', '-m', message)
    except subprocess.CalledProcessError:
      logging.debug('No changes, skipping git push.')
      return

    self._git('push', 'origin', branch)

  def upload_crashes(self, name, directory):
    """Uploads the crashes at |directory| to |name|."""
    return self._ci_filestore.upload_crashes(name, directory)

  def upload_corpus(self, name, directory, replace=False):
    """Uploads the corpus at |directory| to |name|."""
    self._upload_to_git('Corpus upload',
                        self.config.git_store_branch,
                        os.path.join(_CORPUS_DIR, name),
                        directory,
                        replace=replace)

  def upload_build(self, name, directory):
    """Uploads the build at |directory| to |name|."""
    return self._ci_filestore.upload_build(name, directory)

  def upload_coverage(self, name, directory):
    """Uploads the coverage report at |directory| to |name|."""
    self._upload_to_git('Coverage upload',
                        self.config.git_store_branch_coverage,
                        os.path.join(_COVERAGE_DIR, name),
                        directory,
                        replace=True)

  def download_corpus(self, name, dst_directory):
    """Downloads the corpus located at |name| to |dst_directory|."""
    self._reset_git(self.config.git_store_branch)
    path = os.path.join(self.repo_path, _CORPUS_DIR, name)
    if not os.path.exists(path):
      logging.debug('Corpus does not exist at %s.', path)
      return False

    shutil.copytree(path, dst_directory, dirs_exist_ok=True)
    return True

  def download_build(self, name, dst_directory):
    """Downloads the build with |name| to |dst_directory|."""
    return self._ci_filestore.download_build(name, dst_directory)

  def download_coverage(self, name, dst_directory):
    """Downloads the latest project coverage report."""
    self._reset_git(self.config.git_store_branch_coverage)
    path = os.path.join(self.repo_path, _COVERAGE_DIR, name)
    if not os.path.exists(path):
      logging.debug('Coverage does not exist at %s.', path)
      return False

    shutil.copytree(path, dst_directory, dirs_exist_ok=True)
    return True
