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

import build_specified_commit


class RepoManagerError(Exception):
  """Class to describe the exceptions in RepoManager."""


class RepoManager:
  """Class to manage git repos from python.

  Attributes:
    repo_url: The location of the git repo
    base_dir: The location of where the repo clone is stored locally
    repo_name: The name of the github project
    repo_dir: The location of the main repo
  """

  def __init__(self, repo_url, base_dir, repo_name=None):
    """Constructs a repo manager class.

    Args:
      repo_url: The github url needed to clone
      base_dir: The full filepath where the git repo is located
      repo_name: The name of the directory the repo is cloned to
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
        RepoManagerError if the repo was not able to be cloned
    """
    if not os.path.exists(self.base_dir):
      os.makedirs(self.base_dir)
    self.remove_repo()
    out, err = build_specified_commit.execute(
        ['git', 'clone', self.repo_url, self.repo_name], location=self.base_dir)
    if not self._is_git_repo():
      raise RepoManagerError('%s is not a git repo' % self.repo_url)

  def _is_git_repo(self):
    """Test if the current repo dir is a git repo or not.

    Returns:
      True if the current repo_dir is a valid git repo
    """
    git_path = os.path.join(self.repo_dir, '.git')
    return os.path.isdir(git_path)

  def commit_exists(self, commit):
    """Checks to see if a commit exists in the project repo.

    Args:
      commit: The commit SHA you are checking

    Returns:
      True if the commit exits in the project

    Raises:
      ValueException: an empty string was passed in as a commit
    """

    # Handle the exception case, if empty string is passed execute will
    # raise a ValueError
    if not commit.rstrip():
      raise RepoManagerError('An empty string is not a valid commit SHA')

    _, err_code = build_specified_commit.execute(
        ['git', 'cat-file', '-e', commit], self.repo_dir)
    return not err_code

  def get_current_commit(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA
    """
    out, _ = build_specified_commit.execute(['git', 'rev-parse', 'HEAD'],
                                            self.repo_dir,
                                            check_result=True)
    return out.strip('\n')

  def get_commit_list(self, old_commit, new_commit):
    """Gets the list of commits(inclusive) between the old and new commits.

    Args:
      old_commit: The oldest commit to be in the list
      new_commit: The newest commit to be in the list

    Returns:
      The list of commit SHAs from newest to oldest

    Raises:
      RepoManagerError when commits dont exist
    """

    if not self.commit_exists(old_commit):
      raise RepoManagerError('The old commit %s does not exist' % old_commit)
    if not self.commit_exists(new_commit):
      raise RepoManagerError('The new commit %s does not exist' % new_commit)
    if old_commit == new_commit:
      return [old_commit]
    out, err_code = build_specified_commit.execute(
        ['git', 'rev-list', old_commit + '..' + new_commit], self.repo_dir)
    commits = out.split('\n')
    commits = [commit for commit in commits if commit]
    if err_code or not commits:
      raise RepoManagerError('Error getting commit list between %s and %s ' %
                             (old_commit, new_commit))

    # Make sure result is inclusive
    commits.append(old_commit)
    return commits

  def _get_git_history(self):
    """Gets the current git repository history."""
    git_path = os.path.join(self.repo_dir, '.git', 'shallow')
    if os.path.exists(git_path):
      build_specified_commit.execute(['git', 'fetch', '--unshallow'],
                                     self.repo_dir,
                                     check_result=True)

  def checkout_pr(self, pr_ref):
    """Checks out a remote pull request.

    Args:
      pr_ref: The pull request reference to be checked out.

    Raises:
      RepoManagerError: when pull request checkout fails.
    """
    self._get_git_history()

    _, return_code = build_specified_commit.execute(
        ['git', 'fetch', 'origin', pr_ref], self.repo_dir)
    if return_code:
      raise RepoManagerError('Error checking out pull request %s.' % pr_ref)
    _, return_code = build_specified_commit.execute(
        ['git', 'checkout', '-f', 'FETCH_HEAD'], self.repo_dir)
    if return_code:
      raise RepoManagerError('Error fetching head from pull request %s.' %
                             pr_ref)

  def checkout_commit(self, commit):
    """Checks out a specific commit from the repo.

    Args:
      commit: The commit SHA to be checked out

    Raises:
      RepoManagerError when checkout is not successful
    """
    self._get_git_history()
    if not self.commit_exists(commit):
      raise RepoManagerError('Commit %s does not exist in current branch' %
                             commit)
    build_specified_commit.execute(['git', 'checkout', '-f', commit],
                                   self.repo_dir,
                                   check_result=True)
    build_specified_commit.execute(['git', 'clean', '-fxd'],
                                   self.repo_dir,
                                   check_result=True)
    if self.get_current_commit() != commit:
      raise RepoManagerError('Error checking out commit %s' % commit)

  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)
