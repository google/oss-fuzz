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
"""Module to get the the name of a git repo containing a specific commit
inside of an OSS-Fuzz project.

Example Usage:

  python detect_repo.py --src_dir /src --example_commit
    b534f03eecd8a109db2b085ab24d419b6486de97

Prints the location of the git remote repo as well as the repo's name
seperated by a space.

  https://github.com/VirusTotal/yara.git yara

"""
import argparse
import logging
import os
import subprocess


def main():
  """Function to get a git repo's url and name referenced by OSS-Fuzz
  Dockerfile.

  Raises:
    ValueError when a commit or a ref is not provided.
  """
  parser = argparse.ArgumentParser(
      description=
      'Finds a specific git repo in an oss-fuzz project\'s docker file.')
  parser.add_argument('--repo_name', help='The name of the git repo.')
  parser.add_argument('--src_dir', help='The location of the possible repo.')
  parser.add_argument('--example_commit',
                      help='A commit SHA referencing the project\'s main repo.')

  args = parser.parse_args()
  if not args.repo_name and not args.example_commit:
    raise ValueError(
        'Requires an example commit or a repo name to find repo location.')
  if args.src_dir:
    src_dir = args.src_dir
  else:
    src_dir = os.environ.get('SRC', '/src')

  for single_dir in os.listdir(src_dir):
    full_path = os.path.join(src_dir, single_dir)
    if not os.path.isdir(full_path):
      continue
    if args.example_commit and check_for_commit(full_path, args.example_commit):
      print('Detected repo:', get_repo(full_path), full_path)
      return
    if args.repo_name and check_for_repo_name(full_path, args.repo_name):
      print('Detected repo:', get_repo(full_path), full_path)
      return
  logging.error('No git repos with specific commit: %s found in %s',
                args.example_commit, src_dir)


def get_repo(repo_path):
  """Gets a git repo link from a specific directory in a docker image.

  Args:
    repo_path: The directory on the image where the git repo exists.

  Returns:
    The repo location or None.
  """
  output, return_code = execute(['git', 'config', '--get', 'remote.origin.url'],
                                location=repo_path,
                                check_result=True)
  if return_code == 0 and output:
    return output.rstrip()
  return None


def check_for_repo_name(repo_path, repo_name):
  """Check to see if the repo_name matches the remote repository repo name.

  Args:
    repo_path: The directory of the git repo.
    repo_name: The name of the target git repo.
  """
  if not os.path.exists(os.path.join(repo_path, '.git')):
    return False

  out, _ = execute(['git', 'config', '--get', 'remote.origin.url'],
                   location=repo_path)
  out = out.split('/')[-1].replace('.git', '').rstrip()
  return out == repo_name


def check_for_commit(repo_path, commit):
  """Checks a directory for a specific commit.

  Args:
    repo_path: The name of the directory to test for the commit.
    commit: The commit SHA to check for.

  Returns:
    True if directory contains that commit.
  """

  # Check if valid git repo.
  if not os.path.exists(os.path.join(repo_path, '.git')):
    return False

  # Check if history fetch is needed.
  if os.path.exists(os.path.join(repo_path, '.git', 'shallow')):
    execute(['git', 'fetch', '--unshallow'], location=repo_path)

  # Check if commit is in history.
  _, return_code = execute(['git', 'cat-file', '-e', commit],
                           location=repo_path)
  return return_code == 0


def execute(command, location, check_result=False):
  """Runs a shell command in the specified directory location.

  Args:
    command: The command as a list to be run.
    location: The directory the command is run in.
    check_result: Should an exception be thrown on failed command.

  Returns:
    The stdout of the command, the error code.

  Raises:
    RuntimeError: running a command resulted in an error.
  """
  process = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=location)
  output, err = process.communicate()
  if check_result and (process.returncode or err):
    raise RuntimeError(
        'Error: %s\n running command: %s\n return code: %s\n out %s\n' %
        (err, command, process.returncode, output))
  if output is not None:
    output = output.decode('ascii')
  return output, process.returncode


if __name__ == '__main__':
  main()
