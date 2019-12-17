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
import subprocess


class RepoManagerError(Exception):
  """Class to describe the exceptions in RepoManager."""


class RepoManager(object):
  """Class to manage git repos from python.

  Attributes:
    repo_url: The location of the git repo
    base_dir: The location of where the repo clone is stored locally
    repo_name: The name of the github project
    repo_dir: The location of the main repo
  """

  def __init__(self, repo_url, base_dir):
    """Constructs a repo manager class.

    Args:
      repo_url: The github url needed to clone
      base_dir: The full filepath where the git repo is located
    """

    self.repo_url = repo_url
    self.base_dir = base_dir
    self.repo_name = self.repo_url.split('/')[-1].strip('.git')
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
    self._run_command(['git', 'clone', self.repo_url],
                      self.base_dir,
                      check_result=True)
    if not self._is_git_repo():
      raise RepoManagerError('%s is not a git repo' % self.repo_url)

  def _run_command(self, command, location='.', check_result=False):
    """ Runs a shell command in the specified directory location.

    Args:
      command: The command as a list to be run
      location: The directory the command is run in
      check_result: Should an exception be thrown on failed command

    Returns:
      The stdout of the command, the error code

    Raises:
      RepoManagerError: running a command resulted in an error
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=location)
    out, err = process.communicate()
    if check_result and (process.returncode or err):
      raise RepoManagerError(
          'Error: %s running command: %s with return code: %s' %
          (err, command, process.returncode))
    if out is not None:
      out = out.decode('ascii')
    return out, process.returncode

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

    # Handle the exception case, if empty string is passed _run_command will
    # raise a ValueError
    if not commit.rstrip():
      raise ValueError('An empty string is not a valid commit SHA')

    _, err_code = self._run_command(['git', 'cat-file', '-e', commit],
                                    self.repo_dir)
    return not err_code

  def get_current_commit(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA
    """
    out, _ = self._run_command(['git', 'rev-parse', 'HEAD'],
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
    out, err_code = self._run_command(
        ['git', 'rev-list', old_commit + '..' + new_commit], self.repo_dir)
    commits = out.split('\n')
    commits = [commit for commit in commits if commit]
    if err_code or not commits:
      raise RepoManagerError('Error getting commit list between %s and %s ' %
                             (old_commit, new_commit))

    # Make sure result is inclusive
    commits.append(old_commit)
    return commits

  def checkout_commit(self, commit):
    """Checks out a specific commit from the repo.

    Args:
      commit: The commit SHA to be checked out

    Raises:
      RepoManagerError when checkout is not successful
    """
    if not self.commit_exists(commit):
      raise RepoManagerError('Commit %s does not exist in current branch' %
                             commit)

    git_path = os.path.join(self.repo_dir, '.git', 'shallow')
    if os.path.exists(git_path):
      self._run_command(['git', 'fetch', '--unshallow'],
                        self.repo_dir,
                        check_result=True)
    self._run_command(['git', 'checkout', '-f', commit],
                      self.repo_dir,
                      check_result=True)
    self._run_command(['git', 'clean', '-fxd'],
                      self.repo_dir,
                      check_result=True)
    if self.get_current_commit() != commit:
      raise RepoManagerError('Error checking out commit %s' % commit)

  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)
