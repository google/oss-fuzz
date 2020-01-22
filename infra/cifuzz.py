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

import argparse
import enum
import os
import shutil
import sys

import build_specified_commit
import fuzz_target
import helper
import repo_manager
import utils


class Status(enum.Enum):
  BUG_NOT_FOUND=0
  ERROR=1
  BUG_FOUND=2

def main():
  """Connects fuzzers with CI tools.

  Returns:
    0 on success and 1 on failure.
  """
  parser = argparse.ArgumentParser(
      description='Help CI tools manage specific fuzzers.')

  subparsers = parser.add_subparsers(dest='command')
  build_fuzzer_parser = subparsers.add_parser(
      'build_fuzzers', help='Build an OSS-Fuzz projects fuzzers.')
  build_fuzzer_parser.add_argument('project_name')
  build_fuzzer_parser.add_argument('github_repo_name')
  build_fuzzer_parser.add_argument('commit_sha')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzers', help='Run an OSS-Fuzz projects fuzzers.')
  run_fuzzer_parser.add_argument('project_name')
  run_fuzzer_parser.add_argument('fuzz_time')
  args = parser.parse_args()

  # Get the shared volume directory and creates required directory.
  if os.environ['GITHUB_WORKSPACE']:
    git_workspace = os.path.join(os.environ['GITHUB_WORKSPACE'], 'storage')
    if not os.path.exists(git_workspace):
      os.mkdir(git_workspace)
    out_dir = os.path.join(os.environ['GITHUB_WORKSPACE'], 'out')
    if not os.path.exists(out_dir):
      os.mkdir(out_dir)
  else:
    return Status.ERROR

  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)

  if args.command == 'build_fuzzers':
    if build_fuzzers(args, git_workspace, out_dir):
      return Status.BUG_NOT_FOUND
    return Status.ERROR
  if args.command == 'run_fuzzers':
    return run_fuzzers(args, out_dir)
  return Status.ERROR


def build_fuzzers(args, git_workspace, out_dir):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    args: List of args passed in to cifuzz.py build_fuzzers parser.
    git_workspace: The location in the shared volume to store git repos.
    out_dir: The location in the shared volume to store output artifacts.

  Returns:
    True on success False on failure.
  """
  # TODO: Modify build_specified_commit function to return src dir.
  src = '/src'

  inferred_url, oss_fuzz_repo_name = build_specified_commit.detect_main_repo(
      args.project_name, repo_name=args.github_repo_name)
  if not inferred_url or not oss_fuzz_repo_name:
    print('Error: Repo URL or name could not be determined.', file=sys.stderr)

  # Checkout projects repo in the shared volume.
  build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                git_workspace,
                                                repo_name=oss_fuzz_repo_name)
  try:
    build_repo_manager.checkout_commit(args.commit_sha)
  except repo_manager.RepoManagerError:
    print('Error: Specified commit does not exist.', file=sys.stderr)
    return False

  command = [
      '--cap-add', 'SYS_PTRACE', '--volumes-from',
      utils.get_container(), '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
      'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64',
      'gcr.io/oss-fuzz/%s' % args.project_name, '/bin/bash', '-c',
      'rm -rf /src/yara/* && cp -r {0} {1} && compile && cp -r {2} {3}'.format(
          os.path.join(git_workspace, '.'), src, '/out/.', out_dir)
  ]
  if helper.docker_run(command):
    print('Error: Building fuzzers failed.', file=sys.stderr)
    return False
  return True


def run_fuzzers(args, out_dir):
  """Runs a all fuzzers for a specific OSS-Fuzz project.

  Args:
    args: List of args passed in to cifuzz.py run_fuzzers parser.
    out_dir: The location in the shared volume to store output artifacts.

  Returns:
    A status enum representing the state of the run.
  """
  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    print('Error: No fuzzers were found in out directory.', file=sys.stderr)
    return Status.ERROR

  fuzzer_timeout = int(int(args.fuzz_time) / len(fuzzer_paths))
  fuzz_targets = []
  for fuzzer_path in fuzzer_paths:
    fuzz_targets.append(
        fuzz_target.FuzzTarget(args.project_name, fuzzer_path, fuzzer_timeout))

  for target in fuzz_targets:
    test_case, stack_trace = target.start()
    if not test_case or not stack_trace:
      print('Fuzzer {} finished running.'.format(target.target_name))
    else:
      print("Fuzzer {} Detected Error: {}".format(target.target_name,
                                                  stack_trace),
            file=sys.stderr)
      shutil.move(os.path.join(os.path.dirname(target.target_path), test_case),
                  '/tmp/testcase')
      return Status.BUG_FOUND
  return Status.BUG_NOT_FOUND


if __name__ == '__main__':
  sys.exit(main())
