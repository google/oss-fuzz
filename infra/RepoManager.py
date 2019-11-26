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


class RepoManager(object):
  """Class to manage git repos from python.

  Attributes:
    repo_url: The location of the git repo
    local_dir: The location of where the repo clone is stored locally
    repo_name: The name of the github project
    repo_dir: The location of the main repo

  """

  repo_url = ''
  repo_name  = ''
  repo_dir = ''
  local_dir = ''


  def __init__(self, repo_url, branch=None, commit=None, local_dir=''):
    """Constructs a repo manager class.

    Args:
      repo_url: The github url needed to clone
      branch: The specified branch to be checked out
      commit: The specified commit to be checked out
      local_dir: The local location the repo will live in
    """

    self.repo_url = repo_url
    self.local_dir = local_dir
    self.repo_name =  self.repo_url.split('/')[-1].strip('.git')
    self.repo_dir = os.path.join(self.local_dir, self.repo_name)
    self._clone()
    if branch is not None:
      self.checkout(branch)

    if commit is not None:
      self.checkout_commit(commit)


  def _clone(self):
    """Creates a clone of the repo in the specified directory."""
    if not os.path.exists(self.local_dir):
      os.makedirs(self.local_dir)
  
    self.remove_repo()
    _, err = self._run_command(['git', 'clone', self.repo_url], self.local_dir)
    if err is not None:
      return 1
    return 0


  def _run_command(self, command, location):
    """ Runs a shell command in the specified directory location.

    Args:
      command: The command as a list to be run

    Returns:
      The stdout of the command, the stderr of the command
    """
    cur_dir  = os.getcwd()
    os.chdir(location)
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    out, err = process.communicate()
    os.chdir(cur_dir)
    if err is not None:
      err = err.decode('ascii')
      print("Error %s running command %s" % (err, command))
    if out is not None:
      out = out.decode('ascii')
    return out, err


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

    out, err = self._run_command(['git', 'branch', '--contains', commit], self.repo_dir)
    if ('error: no such commit' in out) or ('error: malformed object name' in out) or (out is ''):
      return False
    else:
      return True


  def get_current_SHA(self):
    """Gets the current commit SHA of the repo.

    Returns:
      The current active commit SHA
    """
    out, err = self._run_command(['git', 'rev-parse', 'HEAD'], self.repo_dir)
    if err is not None:
      return 1
    else:
      return out.strip('\n')


  def checkout_commit(self, commit):
    """Checks out a specific commit from the repo.

    Args:
      commit: The commit SHA to be checked out

    Returns:
      0 on success or 1 on failure
    """
    if not self._commit_exists(commit):
      print("Commit %s does not exist in current branch" % commit)
      return 1

    git_path = os.path.join(self.repo_dir, '.git','shallow')
    if os.path.exists(git_path):
      _, err = self._run_command(['git', 'fetch', '--unshallow'], self.repo_dir)
      if err is not None:
        return 1

    out, err = self._run_command(['git', 'checkout', '-f', commit], self.repo_dir)
    return 0


  def remove_repo(self):
    """Attempts to remove the git repo. """
    if os.path.isdir(self.repo_dir):
      shutil.rmtree(self.repo_dir)


