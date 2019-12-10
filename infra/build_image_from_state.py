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
import sys
import subprocess

from helper import build_image_impl
from helper import check_project_exists
from helper import docker_run
from helper import env_to_docker_args
from helper import get_absolute_path
from helper import get_command_string
from helper import get_dockerfile_path
from helper import get_output_dir
from helper import get_work_dir
from helper import workdir_from_dockerfile
from RepoManager import RepoManager


def build_fuzzer_from_commit(project_name, commit, fuzzer_name, local_store_path,
                              engine='libfuzzer',
                              sanitizer='address',
                              architecture='x86_64'):
  """Builds a ossfuzz fuzzer at a  specific commit SHA.

  Args:
    project_name: The oss fuzz project name
    commit: The commit SHA to build the fuzzers at
    fuzzer_name: The name of the fuzzer that needs to be built
    local_store_path: The full file path of a place where a temp git repo is stored
    engine: The fuzzing engine to be used
    sanitizer: The fuzzing sanitizer to be used
    architecture: The system architiecture to be used for fuzzing

  Returns:
    0 on successful build 1 on failure
  """
  guessed_url = infer_main_repo(project_name, local_store_path, commit)
  repo_man = RepoManager(guessed_url, local_store_path)
  repo_man.checkout_commit(commit)
  build_image_impl(project_name)
  project_out_dir = get_output_dir(project_name)

  # Clean old and possibly conflicting artifacts in project's out directory.
  docker_run([
      '-v', '%s:/out' % project_out_dir,
      '-t', 'gcr.io/oss-fuzz/%s' % project_name,
      '/bin/bash', '-c', 'rm -rf /out/*'
  ])

  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer,
      'ARCHITECTURE=' + architecture,
  ]

  project_work_dir = get_work_dir(project_name)
  # Copy instrumented libraries.
  if sanitizer == 'memory':
    docker_run([
        '-v', '%s:/work' % project_work_dir,
        'gcr.io/oss-fuzz-base/msan-builder',
        'bash', '-c', 'cp -r /msan /work'])
    env.append('MSAN_LIBS_PATH=' + '/work/msan')

  command = (
      ['docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE'] +
      env_to_docker_args(env))

  command += [
      '-v', '%s:/src/%s' % (repo_man.repo_dir, project_name),
      '-v', '%s:/out' % project_out_dir,
      '-v', '%s:/work' % project_work_dir,
      '-t', 'gcr.io/oss-fuzz/%s' % project_name
  ]

  print('Running:', get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('Fuzzers build failed.', file=sys.stderr)
    return 1

  # Patch MSan builds to use instrumented shared libraries.
  if sanitizer == 'memory':
    docker_run([
        '-v', '%s:/out' % project_out_dir,
        '-v', '%s:/work' % project_work_dir
    ] + env_to_docker_args(env) + [
        'gcr.io/oss-fuzz-base/base-msan-builder',
        'patch_build.py', '/out'
    ])
  return 0


def infer_main_repo(project_name, local_store_path, example_commit=None):
  """Tries to guess the main repo a project based on the Dockerfile.

  NOTE: This is a fragile implementation and only works for git
  Args:
    project_name: The oss fuzz project that you are checking the repo of
    example_commit: A commit that is in the main repos tree
  Returns:
    The guessed repo url path or 1 on failue
  """
  if not check_project_exists(project_name):
    return 1
  docker_path = get_dockerfile_path(project_name)
  with open(docker_path, 'r') as fp:
    lines = ''.join(fp.readlines())
    # Use generic git format and project name to guess main repo
    if example_commit is None:
      repo_url = re.search(r'\bhttp[^ ]*' + re.escape(project_name) + r'.git', lines)
      if repo_url:
        return repo_url.group(0)
      repo_url = re.search(r'\bgit:[^ ]*/' + re.escape(project_name), lines)
      if repo_url:
        return repo_url.group(0)

  # Use example commit SHA to guess main repo
    else:
      for clone_command in re.findall('.*clone.*', lines):
        print(clone_command)
        for git_repo_url in re.findall('http[s]?://[^ ]*',
                                       clone_command):
          print(git_repo_url)
          rm = RepoManager(git_repo_url.rstrip(), local_store_path)
          if rm.commit_exists(example_commit):
            return git_repo_url
  return 1
