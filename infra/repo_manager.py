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
import os
import shutil

import utils


class RepoManager:
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
      self.repo_name = os.path.basename(self.repo_url).strip('.git')
    self.repo_dir = os.path.join(self.base_dir, self.repo_name)
    self._clone()

  def _clone(self):
    """Creates a clone of the repo in the specified directory.

      Raises:
        ValueError: when the repo is not able to be cloned.
    """
    if not os.path.exists(self.base_dir):
      os.makedirs(self.base_dir)
    self.remove_repo()
    out, err = utils.execute(['git', 'clone', self.repo_url, self.repo_name],
                             location=self.base_dir)
    if not self._is_git_repo():
      raise ValueError('%s is not a git repo' % self.repo_url)

  def _is_git_repo(self):
    """Test if the current repo dir is a git repo or not.

    Returns:
      True if the current repo_dir is a valid git repo.
    """
    git_path = os.path.join(self.repo_dir, '.git')
    return os.path.isdir(git_path)

  def commit_exists(self, commit):
    """Checks to see if a commit exists in the project repo.

    Args:
      commit: The commit SHA you are checking.

    Returns:
      True if the commit exits in the project.
    """
    if not commit.rstrip():
      return False

    _, err_code = utils.execute(['git', 'cat-file', '-e', commit],
                                self.repo_dir)
    return not err_code

  def get_current_commit(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA.
    """
    out, _ = utils.execute(['git', 'rev-parse', 'HEAD'],
                           self.repo_dir,
                           check_result=True)
    return out.strip('\n')

  def get_commit_list(self, old_commit, new_commit):
    """Gets the list of commits(inclusive) between the old and new commits.

    Args:
      old_commit: The oldest commit to be in the list.
      new_commit: The newest commit to be in the list.

    Returns:
      The list of commit SHAs from newest to oldest.

    Raises:
      ValueError: When either the old or new commit does not exist.
      RuntimeError: When there is an error getting the commit list.
    """

    if not self.commit_exists(old_commit):
      raise ValueError('The old commit %s does not exist' % old_commit)
    if not self.commit_exists(new_commit):
      raise ValueError('The new commit %s does not exist' % new_commit)
    if old_commit == new_commit:
      return [old_commit]
    out, err_code = utils.execute(
        ['git', 'rev-list', old_commit + '..' + new_commit], self.repo_dir)
    commits = out.split('\n')
    commits = [commit for commit in commits if commit]
    if err_code or not commits:
      raise RuntimeError('Error getting commit list between %s and %s ' %
                         (old_commit, new_commit))

    # Make sure result is inclusive
    commits.append(old_commit)
    return commits

  def fetch_unshallow(self):
    """Gets the current git repository history."""
    git_path = os.path.join(self.repo_dir, '.git', 'shallow')
    if os.path.exists(git_path):
      utils.execute(['git', 'fetch', '--unshallow'],
                    self.repo_dir,
                    check_result=True)

  def checkout_pr(self, pr_ref):
    """Checks out a remote pull request.

    Args:
      pr_ref: The pull request reference to be checked out.
    """
    self.fetch_unshallow()
    utils.execute(['git', 'fetch', 'origin', pr_ref],
                  self.repo_dir,
                  check_result=True)
    utils.execute(['git', 'checkout', '-f', 'FETCH_HEAD'],
                  self.repo_dir,
                  check_result=True)

  def checkout_commit(self, commit):
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
    utils.execute(['git', 'checkout', '-f', commit],
                  self.repo_dir,
                  check_result=True)
    utils.execute(['git', 'clean', '-fxd'], self.repo_dir, check_result=True)
    if self.get_current_commit() != commit:
      raise RuntimeError('Error checking out commit %s' % commit)

  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)
