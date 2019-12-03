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
"""Uses bisection to determine which commit a bug was introduced and fixed.
This module takes a high and a low commit SHA, a repo name, and a bug.
The module bisects the high and low commit SHA searching for the location
where the bug was introduced. It also looks for where the bug was solved.
This is done with the following steps:
  Typical usage example:
    1. (Host) Clone the main project repo on the host
    2. (Host) Run git fetch --unshallow
    3. (Host) Use git bisect to identify the next commit to check
    4. (Client) Build the image at the specific commit using git hooks
    5. (Host) Build the fuzzers from new image with updated repo
    6. (Host) Test for bug’s existence
    7. Go to step 3
    python bisect.py --project_name curl
      --commit_new 7627a2dd9d4b7417672fdec3dc6e7f8d3de379de
      --commit_old e80b5c801652bdd8aa302345954c3ef8050d039a
      --bug bug_data
"""

import argparse
import os
import subprocess
import shutil

from helper import _check_project_exists
from helper import _get_dockerfile_path
from helper import _build_image_from_commit
from helper import build_fuzzers
from helper import reproduce
LOCAL_GIT_DIR = 'tmp_git'


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class NoRepoFoundException(Error):
  """Occurs when the bisector cant infer the main repo."""
  pass


class NoBugFoundException(Error):
  """When the bisection finishes and no bug has been found."""
  pass


class ProjectNotFoundException(Error):
  """No project could be found with given name."""
  pass


def main():
  parser = argparse.ArgumentParser('bisector.py',
      description='git bisection for finding introduction of bugs')

  parser.add_argument('--project_name',
                      help='The name of the project where the bug occured',
                      required=True)
  parser.add_argument('--commit_new',
                      help='The newest commit SHA to be bisected',
                      required=True)
  parser.add_argument('--commit_old',
                      help='The oldest commit SHA to be bisected',
                      required=True)
  parser.add_argument('--fuzzer_name', help='the bug to be searched for',
                      required=True)
  parser.add_argument('--bug', help='the bug to be searched for',
                      required=True)
  args = parser.parse_args()

  # Remove the temp copy of repos from previous runs
  try:
    remove(LOCAL_GIT_DIR)
  except ValueError:
    pass

  # Create a temp copy of the repo for bisection purposes
  try:
    repo_name = infer_main_repo(args.project_name)
  except ProjectNotFoundException:
    print("Error project %s was not found under oss fuzz project" % args.project_name)
    return 1
  except NoRepoFoundException:
    print("Error the main repo of %s was not able to be inferred" % args.project_name)
    return 1
  clone_repo_local(repo_name)

  # Make sure both commit SHAs exist in the repo
  if not commit_exists(args.commit_new,  args.project_name):
    print("Error: your commit_new SHA %s does not exist in project %s." % (args.commit_new, args.project_name))
    return 1
  if not commit_exists(args.commit_old,  args.project_name):
    print("Error: your commit_old SHA %s does not exist in project %s." % (args.commit_old, args.project_name))
    return 1

  # Begin bisection
  commit_list = get_commit_SHA_list(args.commit_old, args.commit_new, args.project_name)
  print(commit_list)
  result_commit_idx = bisection(0, len(commit_list) - 1, commit_list, args.project_name, -1, args.bug, args.fuzzer_name)
  if result_commit_idx == -1:
    print("No error was found in commit range %s to %s" % (args.commit_old, args.commit_new))
  else:
    print("Error was introduced at commit %s" % commit_list[result_commit_idx])


def build_fuzzers_from_helper(project_name):
  """Builds fuzzers using helper.py api.
  Args:
    project_name: the name of the project whos fuzzers you want build
  """
  parser = argparse.ArgumentParser()
  parser.add_argument('project_name')
  parser.add_argument('fuzzer_name', nargs='?')
  parser.add_argument('--engine', default='libfuzzer')
  parser.add_argument(
      '--sanitizer',
      default="address",
      help='the default is "address"; "dataflow" for "dataflow" engine')
  parser.add_argument('--architecture', default='x86_64')
  parser.add_argument(
      '-e', action='append', help="set environment variable e.g. VAR=value")
  parser.add_argument('source_path', help='path of local source', nargs='?')
  parser.add_argument(
      '--clean',
      dest='clean',
      action='store_true',
      help='clean existing artifacts.')
  parser.add_argument(
      '--no-clean',
      dest='clean',
      action='store_false',
      help='do not clean existing artifacts '
      '(default).')
  parser.set_defaults(clean=False)
  args = parser.parse_args([project_name])
  build_fuzzers(args)


def reproduce_error(project_name, bug, fuzzer_name):
  """Checks to see if the error is repoduceable at a specific commit.
  Args:
    project_name: The name of the project you are testing
    bug: The path to the bug you are passing in
    fuzzer_name: The name of the fuzz target to be tested
  Returns:
    True if the error still exists
  """
  parser = argparse.ArgumentParser()
  parser.add_argument('project_name', help='name of the project')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('testcase_path', help='path of local testcase')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                                nargs=argparse.REMAINDER)
  parser.add_argument('--valgrind', action='store_true',
                                help='run with valgrind')

  parser.add_argument(
      '-e', action='append', help="set environment variable e.g. VAR=value")

  args = parser.parse_args([project_name, fuzzer_name, bug])
  print("Reproduce Result: " + str(reproduce(args)))



def test_error_exists(commit, project_name, bug, fuzzer_name):
  """Tests if the error is reproduceable at the specified commit
  Args:
    commit: The commit you want to check for the error
    project_name: The name of the project we are searching in
    bug: The fuzz bug that we are searching for
    fuzzer_name: The name of the fuzz target you want tested
  Returns:
    True if the error exists at the specified commit
  """

  # Need to change directory for build to work properly
  cur_dir = os.getcwd()
  os.chdir('..')
  _build_image_from_commit(project_name, commit)
  build_fuzzers_from_helper(project_name)
  reproduce_error(project_name, bug, fuzzer_name)
  os.chdir(cur_dir)
  return  False


def bisection(commit_old_idx, commit_new_idx, commit_list, project_name, last_error, bug, fuzzer_name):
  """Returns the commit ID where a bug was introduced.
  Args:
    commit_old_idx: The oldest commit SHA index in the search space
    commit_new_idx: The newest commit SHA index in the search space
    commit_list: The list of all commit SHAs
    project_name: The name of the project we are searching for
    last_error: The index where the last error was found
    bug: The fuzz target to be checked
    fuzzer_name: The name of the fuzz target you want tested
  Returns:
    The SHA string inbetween the low and high where the bug was introduced
  """

  print("Low:  %s High: %s" % (commit_old_idx, commit_new_idx))
  cur_idx = (commit_new_idx + commit_old_idx)//2
  print("Mid: %s" % cur_idx)
  error_exists = test_error_exists(commit_list[cur_idx], project_name, bug, fuzzer_name)

  if commit_new_idx == commit_old_idx:
    if error_exists:
      return cur_idx
    else:
      return last_error
  if error_exists:
    return bisection(commit_old_idx, cur_idx - 1, commit_list, project_name, cur_idx, bug, fuzzer_name)
  else:
    return bisection(cur_idx + 1, commit_new_idx, commit_list, project_name, last_error, bug, fuzzer_name)


def get_commit_SHA_list(commit_old, commit_new, project_name):
  """Gets the commit SHA between two SHAs for a specific project
  Args:
    commit_old: The lower bound SHA
    commit_new: The upper bound SHA
    project_name: The project the SHA's relate to
  Returns:
    The commit SHA between the lower and upper bound SHAs
  Raises:
    ValueError: When the get SHA shell call fails
  """
  out, err = run_command_in_repo(['git', 'rev-list', commit_old + '..' + commit_new], project_name)
  if err is not None:
    raise ValueError('Error getting commit SHAs %s through %s from project %s' % (commit_old, commit_new, project_name))
  return out.split('\n')

def remove(path):
  """Attempts to remove a file or folder from the os
  Args:
    path: the location of what you are trying to remove
  Raises:
    ValueError: if there was no file found with the corispoding path
  """
  if os.path.isfile(path):
      os.remove(path)  # remove the file
  elif os.path.isdir(path):
      shutil.rmtree(path)  # remove dir and all contains
  else:
      raise ValueError("file {} is not a file or dir.".format(path))


def infer_main_repo(project_name):
  """ Trys to guess the main repo of the project based on the Dockerfile.
  Args:
    project_name: The name of the project you are testing
  Returns:
    The guessed repo url path
  Raises:
    NoRepoFoundException: if the repo can't be inferred
    ProjectNotFoundException: if the project passed in is not in oss fuzz
  """
  if not _check_project_exists(project_name):
    raise ProjectNotFoundException('No project could be found with name %s' % project_name)
  docker_path = _get_dockerfile_path(project_name)
  with open(docker_path, 'r') as fp:
    for r in fp.readlines():
      for part_command in r.split(' '):
        if '/' + str(project_name) + '.git' in part_command:
          return part_command
  raise NoRepoFoundException('No repos were found with name %s in docker file %s' % (project_name, docker_path))


def commit_exists(commit, project_name):
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

  out, err = run_command_in_repo(['git', 'branch', '--contains', commit], project_name)
  if ('error: no such commit' in out) or ('error: malformed object name' in out) or (out is ''):
    return False
  else:
    return True


def run_command_in_repo(command, project_name):
  """ Runs a command in the project_name repo.
  This runs under the precondition that clone_repo_local has allready been run.
  Args:
    command: The command as a list to be run
    project_name: The name of the project where the command should be run
  Returns:
    The stdout of the command, the stderr of the command
  """
  cur_dir = os.getcwd()
  os.chdir(LOCAL_GIT_DIR + '/' + project_name)
  process = subprocess.Popen(command, stdout=subprocess.PIPE)
  out, err = process.communicate()
  os.chdir(cur_dir)
  if err is not None:
    err = err.decode('ascii')
  if out is not None:
    out = out.decode('ascii')
  return out, err


def run_command_in_tmp(command):
  """ Runs a command in a temporary workspace.
  Args:
    command: the command as a list
  """
  cur_dir = os.getcwd()
  os.chdir(LOCAL_GIT_DIR)
  subprocess.check_call(command)
  os.chdir(cur_dir)


def clone_repo_local(repo_name):
  """ creates a local clone of a repo in the temp workspace
  Args:
    repo_name: The url path of the repo to clone
  """

  # Attempt to remove outdated dirs
  try: 
    remove(LOCAL_GIT_DIR)
  except ValueError:
    pass

  os.mkdir(LOCAL_GIT_DIR)
  run_command_in_tmp(['git', 'clone', repo_name])

if __name__ == '__main__':
  main()
