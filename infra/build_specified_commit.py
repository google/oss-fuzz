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
<<<<<<< HEAD:infra/utils.py
"""Utilities for OSS-Fuzz infrastructure."""

=======
"""Module to build a image from a specific commit, branch or pull request

This module is allows each of the OSS Fuzz projects fuzzers to be built
from a specific point in time. This feature can be used for implementations
like continuious integration fuzzing and bisection to find errors
"""
>>>>>>> Updating RepoManager tests:infra/build_specified_commit.py
import os
import collections
import re
<<<<<<< HEAD:infra/utils.py
import stat

import helper

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']
FUZZ_TARGET_SEARCH_STRING = 'LLVMFuzzerTestOneInput'
VALID_TARGET_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


def chdir_to_root():
  """Changes cwd to OSS-Fuzz root directory."""
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)


def is_fuzz_target_local(file_path):
  """Returns whether |file_path| is a fuzz target binary (local path).
  Copied from clusterfuzz src/python/bot/fuzzers/utils.py
  with slight modifications.
  """
  filename, file_extension = os.path.splitext(os.path.basename(file_path))
  if not VALID_TARGET_NAME.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not os.path.exists(file_path) or not os.access(file_path, os.X_OK):
    return False

  if filename.endswith('_fuzzer'):
    return True

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    return False

  with open(file_path, 'rb') as file_handle:
    return file_handle.read().find(FUZZ_TARGET_SEARCH_STRING.encode()) != -1


def get_fuzz_targets(path):
  """Get list of fuzz targets in a directory.

  Args:
    path: A path to search for fuzz targets in.

  Returns:
    A list of paths to fuzzers or an empty list if None.
  """
  if not os.path.exists(path):
    return []
  fuzz_target_paths = []
  for root, _, _ in os.walk(path):
    for filename in os.listdir(path):
      file_path = os.path.join(root, filename)
      if is_fuzz_target_local(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def get_container_name():
  """Gets the name of the current docker container you are in.
  /proc/self/cgroup can be used to check control groups e.g. Docker.
  See: https://docs.docker.com/config/containers/runmetrics/ for more info.

  Returns:
    Container name or None if not in a container.
  """
  with open('/proc/self/cgroup') as file_handle:
    if 'docker' not in file_handle.read():
      return None
  with open('/etc/hostname') as file_handle:
    return file_handle.read().strip()
=======
import subprocess

import helper

BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])


def build_fuzzers_from_commit(commit, build_repo_manager, build_data):
  """Builds a OSS-Fuzz fuzzer at a  specific commit SHA.

  Args:
    commit: The commit SHA to build the fuzzers at.
    build_repo_manager: The OSS-Fuzz project's repo manager to be built at.
    build_data: A struct containing project build information.
  Returns:
    0 on successful build or error code on failure.
  """
  build_repo_manager.checkout_commit(commit)
  return helper.build_fuzzers_impl(project_name=build_data.project_name,
                                   clean=True,
                                   engine=build_data.engine,
                                   sanitizer=build_data.sanitizer,
                                   architecture=build_data.architecture,
                                   env_to_add=None,
                                   source_path=build_repo_manager.repo_dir,
                                   mount_location=os.path.join(
                                       '/src', build_repo_manager.repo_name))


def detect_main_repo(project_name, repo_name=None, commit=None, src_dir='/src'):
  """Checks a docker image for the main repo of an OSS-Fuzz project.

  Note: The default is to use the repo name to detect the main repo.

  Args:
    project_name: The name of the oss-fuzz project.
    repo_name: The name of the main repo in an OSS-Fuzz project.
    commit: A commit SHA that is associated with the main repo.
    src_dir: The location of the projects source on the docker image.

  Returns:
    The repo's origin, the repo's name.
  """
  # TODO: Add infra for non hardcoded '/src'.
  if not repo_name and not commit:
    print('Error: can not detect main repo without a repo_name or a commit.')
    return None, None
  if repo_name and commit:
    print('Both repo name and commit specific. Using repo name for detection.')

  helper.build_image_impl(project_name)
  docker_image_name = 'gcr.io/oss-fuzz/' + project_name
  command_to_run = [
      'docker', 'run', '--rm', '-t', docker_image_name, 'python3',
      os.path.join(src_dir, 'detect_repo.py'), '--src_dir', src_dir
  ]
  if repo_name:
    command_to_run.extend(['--repo_name', repo_name])
  else:
    command_to_run.extend(['--example_commit', commit])
  out, _ = execute(command_to_run)
  match = re.search(r'\bDetected repo: ([^ ]+) ([^ ]+)', out.rstrip())
  if match and match.group(1) and match.group(2):
    return match.group(1), match.group(2)
  return None, None


def execute(command, location=None, check_result=False):
  """ Runs a shell command in the specified directory location.

  Args:
    command: The command as a list to be run.
    location: The directory the command is run in.
    check_result: Should an exception be thrown on failed command.

  Returns:
    The stdout of the command, the error code.

  Raises:
    RuntimeError: running a command resulted in an error.
  """

  if not location:
    location = os.getcwd()
  process = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=location)
  out, err = process.communicate()
  if check_result and (process.returncode or err):
    raise RuntimeError('Error: %s\n Command: %s\n Return code: %s\n Out: %s' %
                       (err, command, process.returncode, out))
  if out is not None:
    out = out.decode('ascii')
  return out, process.returncode
>>>>>>> Updating RepoManager tests:infra/build_specified_commit.py
