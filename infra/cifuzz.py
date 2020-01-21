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
import logging
import os
import shutil
import sys

import build_specified_commit
import helper
import repo_manager
import utils


def main():
  """Connects Fuzzers with CI tools.

  Returns:
    True on success False on failure.
  """
  logging.basicConfig(
      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
      stream=sys.stdout,
      level=logging.DEBUG)
  parser = argparse.ArgumentParser(
      description='Help CI tools manage specific fuzzers.')

  subparsers = parser.add_subparsers(dest='command')
  build_fuzzer_parser = subparsers.add_parser(
      'build_fuzzers', help='Build an OSS-Fuzz projects fuzzers.')
  build_fuzzer_parser.add_argument('project_name')
  build_fuzzer_parser.add_argument('repo_name')
  build_fuzzer_parser.add_argument('commit_sha')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzers', help='Run an OSS-Fuzz projects fuzzers.')
  run_fuzzer_parser.add_argument('project_name')
  args = parser.parse_args()

  # Get the shared volume directory.
  if os.environ['GITHUB_WORKSPACE']:
    git_workspace = os.path.join(os.environ['GITHUB_WORKSPACE'], 'storage')
    if not os.path.exists(git_workspace):
      os.mkdir(git_workspace)
    out_dir = os.path.join(os.environ['GITHUB_WORKSPACE'], 'out')
    if not os.path.exists(out_dir):
      os.mkdir(out_dir)
  else:
    print('Error: The GITHUB_WORKSPACE env variable needs to be set.',
          file=sys.stderr)
    return 1

  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)

  if args.command == 'build_fuzzers':
    if build_fuzzers(args, git_workspace, out_dir):
      return 0
    return 1
  if args.command == 'run_fuzzers':
    if run_fuzzers(args, out_dir):
      return 0
    return 1
  print('Invalid argument option, use build_fuzzers or run_fuzzer.',
        file=sys.stderr)
  return 1


def build_fuzzers(args, git_workspace, out_dir):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    git_workspace: The location in the shared volume to store git repos.
    out_dir: The location in the shared volume to store output artifacts.

  Returns:
    True on success False on failure.
  """
  image_name = 'gcr.io/oss-fuzz/%s' % args.project_name
  src = '/src'

  # TODO: Modify build_specified_commit function to return src dir.
  inferred_url, repo_name = build_specified_commit.detect_main_repo(
      args.project_name, repo_name=args.repo_name)

  if not inferred_url or not repo_name:
    print('Error: Repo URL or name could not be determined.', file=sys.stderr)

  # Checkout projects repo in the shared volume.
  build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                git_workspace,
                                                repo_name=repo_name)
  build_repo_manager.checkout_commit(args.commit_sha)

  command = [
      '--cap-add', 'SYS_PTRACE', '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
      'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64', image_name, '/bin/bash',
      '-c',
      'rm -rf /src/yara && cp -r {0} {1} && compile && cp -r {2} {3}'.format(
          os.path.join(git_workspace, '.'), src, '/out', out_dir)
  ]

  if helper.docker_run(command):
    print('Error: Building fuzzers failed.', file=sys.stderr)
    return False
  return True


def run_fuzzers(args, out_dir):
  """Runs a all fuzzer for a specific OSS-Fuzz project.

  Args:
    out_dir: The location in the shared volume to store output artifacts.

  Returns:
    True on success False on failure.
  """

  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    print('Error: No fuzzers were found in out directory.', file=sys.stderr)
    return False
  print('Fuzzer paths', str(fuzzer_paths))
  fuzz_targets = []
  error_detected = False
  for fuzzer_path in fuzzer_paths:
    fuzz_targets.append(
        fuzz_target.FuzzTarget(args.project_name, fuzzer_path, 40))

  for target in fuzz_targets:
    test_case, stack_trace = target.start()
    if not test_case or not stack_trace:
      logging.debug('Fuzzer {} finished running.'.format(target.target_name))
    else:
      error_detected = True
      print("Fuzzer {} Detected Error: {}".format(target.target_name,
                                                  stack_trace),
            file=sys.stderr)
      shutil.move(test_case, '/tmp/testcase')
      break

  return True


if __name__ == '__main__':
  main()
