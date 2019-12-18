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
import re
import subprocess

import helper
import repo_manager


def build_fuzzer_from_commit(project_name,
                             commit,
                             local_store_path,
                             engine='libfuzzer',
                             sanitizer='address',
                             architecture='x86_64',
                             old_repo_manager=None):
  """Builds a OSS-Fuzz fuzzer at a  specific commit SHA.

  Args:
    project_name: The OSS-Fuzz project name
    commit: The commit SHA to build the fuzzers at
    local_store_path: The full file path of a place where a temp git repo is stored
    engine: The fuzzing engine to be used
    sanitizer: The fuzzing sanitizer to be used
    architecture: The system architiecture to be used for fuzzing

  Returns:
    0 on successful build 1 on failure
  """
  if not old_repo_manager:
    inferred_url = infer_main_repo(project_name, local_store_path, commit)
    old_repo_manager = repo_manager.RepoManager(inferred_url, local_store_path)
  old_repo_manager.checkout_commit(commit)
  return helper.build_fuzzers_impl(
      project_name=project_name,
      clean=True,
      engine=engine,
      sanitizer=sanitizer,
      architecture=architecture,
      env_to_add=None,
      source_path=old_repo_manager.repo_dir,
      mount_location=os.path.join('/src',old_repo_manager.repo_name))


def run_command_in_image(image_name, command):
  """Runs a specific command inside a docker image and returns the results.

  Args:
    image_name: The docker image for the command to be run in
    command: The command to be run in the image

  Returns:
    the output of the command

  Raises:
    ValueError: on commands execution failing
  """
  command_to_run =['docker', 'run', '--rm', '-i', '--privileged']
  command_to_run.extend(command)
  print('Running command: %s' % command_to_run)
  process = subprocess.Popen(command, stdout=subprocess.PIPE)
  out, err = process.communicate()
  if err:
    raise ValueError('Error running command: %s with error: %s' % (command, err.decode('ascii')))
  if process.returncode:
    raise ValueError('Command %s returned with error code: %s' % (command, process.returncode))
  if out:
    return out.decode('ascii')
  return None

def check_docker_for_commit(docker_image_name, dir_name, example_commit):
  """ Checks a docker image directory for a specific commit.

  Args:
    docker_image_name: The name of the projects docker image
    dir_name: The name of the directory to test for the commit
    example_commit: The commit SHA to check for

  Returns:
    True if docker image directory contains that commit
  """
  

def infer_main_repo(project_name, local_store_path, example_commit=None):
  """Tries to guess the main repo a project based on the Dockerfile.

  NOTE: This is a fragile implementation and only works for git
  Args:
    project_name: The OSS-Fuzz project that you are checking the repo of
    example_commit: A commit that is in the main repos tree
  Returns:
    The guessed repo url path or None on failue
  """
  if not helper.check_project_exists(project_name):
    return None
  helper.build_image_impl(project_name)
  docker_image_name = 'gcr.io/oss-fuzz/%s' % (project_name)

  out = run_command_in_image(docker_image_name, ['-t' docker_image_name, 'bash', '-c', 'ls /src'])
  for dirs in out.split(' '):
    if check_docker_for_commit(docker_image_name, dirs, example_commit):
      return dirs
  return None
