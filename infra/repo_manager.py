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
"""Class to manage a git repository via python.

This class is to be used to implement git commands over
a python API and manage the current state of the git repo.

  Typical usage example:

    r_man =  RepoManager('https://github.com/google/oss-fuzz.git')
    r_man.checkout('5668cc422c2c92d38a370545d3591039fb5bb8d4')
"""
import datetime
import logging
import os
import shutil

import utils


class BaseRepoManager:
  """Base repo manager."""

  def __init__(self, repo_dir):
    self.repo_dir = repo_dir

  def _is_git_repo(self):
    """Test if the current repo dir is a git repo or not.

    Returns:
      True if the current repo_dir is a valid git repo.
    """
    git_path = os.path.join(self.repo_dir, '.git')
    return os.path.isdir(git_path)

  def git(self, cmd, check_result=False):
    """Run a git command.

    Args:
      command: The git command as a list to be run.
      check_result: Should an exception be thrown on failed command.

    Returns:
      stdout, stderr, error code.
    """
    return utils.execute(['git'] + cmd,
                         location=self.repo_dir,
                         check_result=check_result)

  def commit_exists(self, commit):
    """Checks to see if a commit exists in the project repo.

    Args:
      commit: The commit SHA you are checking.

    Returns:
      True if the commit exits in the project.
    """
    if not commit.rstrip():
      return False

    _, _, err_code = self.git(['cat-file', '-e', commit])
    return not err_code

  def commit_date(self, commit):
    """Get the date of a commit.

    Args:
      commit: The commit hash.

    Returns:
      A datetime representing the date of the commit.
    """
    out, _, _ = self.git(['show', '-s', '--format=%ct', commit],
                         check_result=True)
    return datetime.datetime.fromtimestamp(int(out))

  def get_git_diff(self):
    """Gets a list of files that have changed from the repo head.

    Returns:
      A list of changed file paths or None on Error.
    """
    self.fetch_unshallow()
    out, err_msg, err_code = self.git(['diff', '--name-only', 'origin...'])
    if err_code:
      logging.error('Git diff failed with error message %s.', err_msg)
      return None
    if not out:
      logging.error('No diff was found.')
      return None
    return [line for line in out.splitlines() if line]

  def get_current_commit(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA.
    """
    out, _, _ = self.git(['rev-parse', 'HEAD'], check_result=True)
    return out.strip('\n')

  def get_commit_list(self, newest_commit, oldest_commit=None):
    """Gets the list of commits(inclusive) between the old and new commits.

    Args:
      newest_commit: The newest commit to be in the list.
      oldest_commit: The (optional) oldest commit to be in the list.

    Returns:
      The list of commit SHAs from newest to oldest.

    Raises:
      ValueError: When either the oldest or newest commit does not exist.
      RuntimeError: When there is an error getting the commit list.
    """
    self.fetch_unshallow()
    if oldest_commit and not self.commit_exists(oldest_commit):
      raise ValueError('The oldest commit %s does not exist' % oldest_commit)
    if not self.commit_exists(newest_commit):
      raise ValueError('The newest commit %s does not exist' % newest_commit)
    if oldest_commit == newest_commit:
      return [oldest_commit]

    if oldest_commit:
      commit_range = oldest_commit + '..' + newest_commit
    else:
      commit_range = newest_commit

    out, _, err_code = self.git(['rev-list', commit_range])
    commits = out.split('\n')
    commits = [commit for commit in commits if commit]
    if err_code or not commits:
      raise RuntimeError('Error getting commit list between %s and %s ' %
                         (oldest_commit, newest_commit))

    # Make sure result is inclusive
    if oldest_commit:
      commits.append(oldest_commit)
    return commits

  def fetch_unshallow(self):
    """Gets the current git repository history."""
    shallow_file = os.path.join(self.repo_dir, '.git', 'shallow')
    if os.path.exists(shallow_file):
      self.git(['fetch', '--unshallow'], check_result=True)

  def checkout_pr(self, pr_ref):
    """Checks out a remote pull request.

    Args:
      pr_ref: The pull request reference to be checked out.
    """
    self.fetch_unshallow()
    self.git(['fetch', 'origin', pr_ref], check_result=True)
    self.git(['checkout', '-f', 'FETCH_HEAD'], check_result=True)

  def checkout_commit(self, commit, clean=True):
    """Checks out a specific commit from the repo.

    Args:
      commit: The commit SHA to be checked out.

    Raises:
      RuntimeError: when checkout is not successful.
      ValueError: when commit does not exist.
    """
    self.fetch_unshallow()
    if not self.commit_exists(commit):
      raise ValueError('Commit %s does not exist in current branch' % commit)
    self.git(['checkout', '-f', commit], check_result=True)
    if clean:
      self.git(['clean', '-fxd'], check_result=True)
    if self.get_current_commit() != commit:
      raise RuntimeError('Error checking out commit %s' % commit)

  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)


class RepoManager(BaseRepoManager):
  """Class to manage git repos from python.

  Attributes:
    repo_url: The location of the git repo.
    base_dir: The location of where the repo clone is stored locally.
    repo_name: The name of the GitHub project.
    repo_dir: The location of the main repo.
  """

  def __init__(self, repo_url, base_dir, repo_name=None):
    """Constructs a repo manager class.

    Args:
      repo_url: The github url needed to clone.
      base_dir: The full file-path where the git repo is located.
      repo_name: The name of the directory the repo is cloned to.
    """
    self.repo_url = repo_url
    self.base_dir = base_dir
    if repo_name:
      self.repo_name = repo_name
    else:
      self.repo_name = os.path.basename(self.repo_url).replace('.git', '')
    repo_dir = os.path.join(self.base_dir, self.repo_name)
    super(RepoManager, self).__init__(repo_dir)

    if not os.path.exists(self.repo_dir):
      self._clone()

  def _clone(self):
    """Creates a clone of the repo in the specified directory.

      Raises:
        ValueError: when the repo is not able to be cloned.
    """
    if not os.path.exists(self.base_dir):
      os.makedirs(self.base_dir)
    self.remove_repo()
    out, _, _ = utils.execute(['git', 'clone', self.repo_url, self.repo_name],
                              location=self.base_dir)
    if not self._is_git_repo():
      raise ValueError('%s is not a git repo' % self.repo_url)
