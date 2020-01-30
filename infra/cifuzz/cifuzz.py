# Copyright 2020 Google LLC
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
"""Module used by CI tools in order to interact with fuzzers.
This module helps CI tools do the following:
  1. Build fuzzers.
  2. Run fuzzers.
Eventually it will be used to help CI tools determine which fuzzers to run.
"""

import logging
import os
import shutil
import sys

import fuzz_target

# pylint: disable=wrong-import-position
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build_specified_commit
import helper
import repo_manager
import utils

# TODO: Turn default logging to WARNING when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def build_fuzzers(project_name,
                  project_repo_name,
                  git_workspace,
                  out_dir,
                  pr_ref=None,
                  commit_sha=None):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz project being built.
    project_repo_name: The name of the projects repo.

    git_workspace: The location in the shared volume to store git repos.
    out_dir: The location in the shared volume to store output artifacts.
    pr_ref: The pull request reference to be built.
    commit_sha: The commit sha for the project to be built at.

  Returns:
    True if build succeeded or False on failure.
  """

  if not os.path.exists(git_workspace):
    logging.error('Invalid git workspace: %s.', format(git_workspace))
    return False
  if not os.path.exists(out_dir):
    logging.error('Invalid out directory %s.', format(out_dir))
    return False

  inferred_url, oss_fuzz_repo_path = build_specified_commit.detect_main_repo(
      project_name, repo_name=project_repo_name)
  if not inferred_url or not oss_fuzz_repo_path:
    logging.error('Could not detect repo from project %s.', project_name)
    return False
  src_in_docker = os.path.dirname(oss_fuzz_repo_path)
  oss_fuzz_repo_name = os.path.basename(oss_fuzz_repo_path)

  # Checkout projects repo in the shared volume.
  build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                git_workspace,
                                                repo_name=oss_fuzz_repo_name)
  if not pr_ref and not commit_sha:
    logging.error('A commit or pull request reference needs to be specified.')
    return False
  try:
    if pr_ref:
      build_repo_manager.checkout_pr(pr_ref)
    else:
      build_repo_manager.checkout_commit(commit_sha)
  except repo_manager.RepoManagerError:
    logging.error('Error checking out pull request.')
    # NOTE: Remove return statement for testing.
    return False

  command = [
      '--cap-add', 'SYS_PTRACE', '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
      'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64'
  ]
  container = utils.get_container_name()
  if container:
    command += ['-e', 'OUT=' + out_dir, '--volumes-from', container]
    bash_command = 'rm -rf {0} && cp -r {1} {2} && compile'.format(
        os.path.join(src_in_docker, oss_fuzz_repo_name, '*'),
        os.path.join(git_workspace, oss_fuzz_repo_name), src_in_docker)
  else:
    command += [
        '-e', 'OUT=' + '/out', '-v',
        '%s:%s' % (os.path.join(git_workspace, oss_fuzz_repo_name),
                   os.path.join(src_in_docker, oss_fuzz_repo_name)), '-v',
        '%s:%s' % (out_dir, '/out')
    ]
    bash_command = 'compile'

  command.extend([
      'gcr.io/oss-fuzz/' + project_name,
      '/bin/bash',
      '-c',
  ])
  command.append(bash_command)

  if helper.docker_run(command):
    logging.error('Building fuzzers failed.')
    return False
  return True


def run_fuzzers(project_name, fuzz_seconds, out_dir):
  """Runs all fuzzers for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz project being built.
    fuzz_seconds: The total time allotted for fuzzing.
    out_dir: The location in the shared volume to store output artifacts.

  Returns:
    (True if run was successful, True if bug was found).
  """
  if not out_dir or not os.path.exists(out_dir):
    logging.error('Unreachable out_dir argument %s.', format(out_dir))
    return False, False

  if not fuzz_seconds or fuzz_seconds < 1:
    logging.error('Fuzz_seconds argument must be greater than 1, but was: %s.',
                  format(fuzz_seconds))
    return False, False

  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    logging.error('No fuzzers were found in out directory: %s.',
                  format(out_dir))
    return False, False

  fuzz_seconds_per_target = fuzz_seconds // len(fuzzer_paths)

  for fuzzer_path in fuzzer_paths:
    target = fuzz_target.FuzzTarget(project_name, fuzzer_path,
                                    fuzz_seconds_per_target, out_dir)
    test_case, stack_trace = target.fuzz()
    if not test_case or not stack_trace:
      logging.info('Fuzzer %s, finished running.', target.target_name)
    else:
      logging.info('Fuzzer %s, detected error: %s.', target.target_name,
                   stack_trace)
      shutil.move(test_case, os.path.join(out_dir, 'testcase'))
      return True, True
  return True, False
