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
"""Module to build a image from a specific commit, branch or pull request

This module is allows each of the OSS Fuzz projects fuzzers to be built
from a specific point in time. This feature can be used for implementations
like continuious integration fuzzing and bisection to find errors
"""
import os
import collections
import logging
import re

import helper
import utils

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


def detect_main_repo(project_name, repo_name=None, commit=None):
  """Checks a docker image for the main repo of an OSS-Fuzz project.

  Note: The default is to use the repo name to detect the main repo.

  Args:
    project_name: The name of the oss-fuzz project.
    repo_name: The name of the main repo in an OSS-Fuzz project.
    commit: A commit SHA that is associated with the main repo.
    src_dir: The location of the projects source on the docker image.

  Returns:
    The repo's origin, the repo's path.
  """

  if not repo_name and not commit:
    logging.error(
        'Error: can not detect main repo without a repo_name or a commit.')
    return None, None
  if repo_name and commit:
    logging.info(
        'Both repo name and commit specific. Using repo name for detection.')

  # Change to oss-fuzz main directory so helper.py runs correctly.
  utils.chdir_to_root()
  if not helper.build_image_impl(project_name):
    logging.error('Error: building %s image failed.', project_name)
    return None, None
  docker_image_name = 'gcr.io/oss-fuzz/' + project_name
  command_to_run = [
      'docker', 'run', '--rm', '-t', docker_image_name, 'python3',
      os.path.join('/src', 'detect_repo.py')
  ]
  if repo_name:
    command_to_run.extend(['--repo_name', repo_name])
  else:
    command_to_run.extend(['--example_commit', commit])
  out, _ = utils.execute(command_to_run)
  match = re.search(r'\bDetected repo: ([^ ]+) ([^ ]+)', out.rstrip())
  if match and match.group(1) and match.group(2):
    return match.group(1), match.group(2)
  return None, None
