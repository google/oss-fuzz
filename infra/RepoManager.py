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
    r_man.getBranch('bisector')
    r_man.close()
"""
import os
import shutil
import subprocess


class RepoManagerException(Exception):
  """Class to describe the exceptions in RepoManager."""

  def __init__(self, message):
    """ Init the exception class.

    Args:
      message: the message to propigate to user
    """
    super().__init__(message)


class RepoManager(object):
  """Class to manage git repos from python.

  Attributes:
    repo_url: The location of the git repo
    local_dir: The location of where the repo clone is stored locally
    repo_name: The name of the github project
    repo_dir: The location of the main repo
    full_path: The full filepath location of the main repo
  """
  repo_url = ''
  repo_name = ''
  repo_dir = ''
  local_dir = ''
  full_path = ''

  def __init__(self, repo_url, commit=None, local_dir='tmp'):
    """Constructs a repo manager class.

    Args:
      repo_url: The github url needed to clone
      commit: The specified commit to be checked out
      local_dir: The local location the repo will live in
    """

    self.repo_url = repo_url
    self.local_dir = local_dir
    self.repo_name = self.repo_url.split('/')[-1].strip('.git')
    self.repo_dir = os.path.join(self.local_dir, self.repo_name)
    self.full_path = os.path.join(os.getcwd(), self.repo_dir)
    self._clone()
    if branch is not None:
      self.checkout(branch)

    if commit is not None:
      self.checkout_commit(commit)

  def _clone(self):
    """Creates a clone of the repo in the specified directory.

      Raises:
        RepoManagerException if the repo was not able to be cloned
    """
    if not os.path.exists(self.local_dir):
      os.makedirs(self.local_dir)
    self.remove_repo()
    _, err = self._run_command(['git', 'clone', self.repo_url], self.local_dir)
    if err is not None:
      raise RepoManagerException(
          'Failed cloning repo %s, with error %s)' % (self.repo_url, err))
    if not self._is_git_repo():
      raise RepoManagerException('%s is not a git repo' % self.repo_url)

  def _run_command(self, command, location='.'):
    """ Runs a shell command in the specified directory location.

    Args:
      command: The command as a list to be run

    Returns:
      The stdout of the command, the stderr of the command
    """
    cur_dir = os.getcwd()
    os.chdir(location)
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    out, err = process.communicate()
    os.chdir(cur_dir)
    if err is not None:
      err = err.decode('ascii')
      print('Error %s running command %s' % (err, command))
    if out is not None:
      out = out.decode('ascii')
    return out, err

  def _is_git_repo(self):
    """Test if the current repo dir is a git repo or not.

    Returns:
      True if the current repo_dir is a valid git repo
    """
    git_path = os.path.join(self.repo_dir, '.git')
    return os.path.isdir(git_path)

  def _commit_exists(self, commit):
    """ Checks to see if a commit exists in the project repo.

    Args:
      commit: The commit SHA you are checking for
      project_name: The name of the project you are checking

    Returns:
      True if the commit exits in the project
    """

    # Handle the default case
    if commit.strip(' ') == '':
      return False

    out, _ = self._run_command(['git', 'branch', '--contains', commit],
                               self.repo_dir)
    if ('error: no such commit' in out) or (
        'error: malformed object name' in out) or (out == ''):
      return False
    return True

  def get_current_commit(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA
    """
    out, err = self._run_command(['git', 'rev-parse', 'HEAD'], self.repo_dir)
    if err is not None:
      return 1
    return out.strip('\n')

  def get_commit_list(self, old_commit, new_commit):
    """Gets the list of commits(inclusive) between the old and new commits.

    Args:
      old_commit: The oldest commit to be in the list
      new_commit: The newest commit to be in the list

    Returns:
      The list of commit SHAs from newest to oldest

    Raises:
      RepoManagerException when commits dont exist
    """

    if not self._commit_exists(old_commit):
      raise RepoManagerException(
          'The old commit %s does not exist' % old_commit)
    if not self._commit_exists(new_commit):
      raise RepoManagerException(
          'The new commit %s does not exist' % new_commit)
    if old_commit == new_commit:
      return [old_commit]
    out, err = self._run_command(
        ['git', 'rev-list', old_commit + '..' + new_commit], self.repo_dir)
    result = out.split('\n')
    result = [i for i in result if i]
    if err is not None or result == []:
      raise RepoManagerException('Error gettign commit list between %s and %s '
                                 % (old_commit, new_commit))

    # Make sure result is inclusive
    result = result + [old_commit]
    return result

  def checkout_commit(self, commit):
    """Checks out a specific commit from the repo.

    Args:
      commit: The commit SHA to be checked out

    Raises:
      RepoManagerException when checkout is not successful
    """
    if not self._commit_exists(commit):
      print('Commit %s does not exist in current branch' % commit)
      raise RepoManagerException(
          'Commit %s does not exist in current branch' % commit)

    git_path = os.path.join(self.repo_dir, '.git', 'shallow')
    if os.path.exists(git_path):
      _, err = self._run_command(['git', 'fetch', '--unshallow'], self.repo_dir)
      if err is not None:
        raise RepoManagerException('Git fetch failed with error %s' % err)

    _, err = self._run_command(['git', 'checkout', '-f', commit], self.repo_dir)
    if self.get_current_commit() != commit:
      raise RepoManagerException('Error checking out commit %s' % commit)

  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)
