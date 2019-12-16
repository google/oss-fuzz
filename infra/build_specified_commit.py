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
import re

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
      source_path=old_repo_manager.repo_dir)


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
  docker_path = helper.get_dockerfile_path(project_name)
  with open(docker_path, 'r') as file_path:
    lines = file_path.read()
    # Use generic git format and project name to guess main repo
    if example_commit is None:
      repo_url = re.search(
          r'\b(?:http|https|git)://[^ ]*' + re.escape(project_name) +
          r'(.git)?', lines)
      if repo_url:
        return repo_url.group(0)
    else:
      # Use example commit SHA to guess main repo
      for clone_command in re.findall('.*clone.*', lines):
        repo_url = re.search(r'\b(?:https|http|git)://[^ ]*',
                             clone_command).group(0)
        print(repo_url)
        try:
          test_repo_manager = repo_manager.RepoManager(repo_url.rstrip(),
                                                       local_store_path)
          if test_repo_manager.commit_exists(example_commit):
            return repo_url
        except:
          pass
    return None
