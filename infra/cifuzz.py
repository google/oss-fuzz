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

  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)

  if args.command == 'build_fuzzers':
    return build_fuzzers(args) == 0
  if args.command == 'run_fuzzers':
    return run_fuzzers(args) == 0
  print('Invalid argument option, use build_fuzzers or run_fuzzer.',
        file=sys.stderr)
  return False


def build_fuzzers(args):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Returns:
    True on success False on failure.
  """
  inferred_url, repo_name = build_specified_commit.detect_main_repo(
      args.project_name, repo_name=args.repo_name)

  if not inferred_url or not repo_name:
    print('Error: Repo URL or name could not be determined.', file=sys.stderr)

  # Get the shared volume directory.
  if os.environ['GITHUB_WORKSPACE']:
    workspace = os.path.join(os.environ['GITHUB_WORKSPACE'], 'storage')
    if not os.path.exists(workspace):
      os.mkdir(workspace)
  else:
    print('Error: needs the GITHUB_WORKSPACE env variable set.',
          file=sys.stderr)
    return 1

  # Get the container name that are currently inside.
  with open('/proc/self/cgroup') as file_handle:
    if 'docker' in file_handle.read():
      with open('/etc/hostname') as file_handle:
        primary_container = file_handle.read().strip()
    else:
      primary_container = None
  if not primary_container:
    print('Error primary container could not be determined.', file=sys.stderr)
    return 1

  # Checkout projects repo in the shared volume.
  build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                workspace,
                                                repo_name=repo_name)
  build_repo_manager.checkout_commit(args.commit_sha)

  if not helper.build_image_impl(args.project_name, no_cache=False):
    print('Error: Building the projects image has failed.', file=sys.stderr)
    return 1

  # Copy the repo from the shared volume to the required location in OSS-Fuzz.
  command = [
      '--cap-add', 'SYS_PTRACE', '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
      'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64'
  ]
  command += [
      '--volumes-from', primary_container,
      'gcr.io/oss-fuzz/%s' % args.project_name
  ]
  command += [
      '/bin/bash', '-c',
      'cp {0} {1} && compile'.format(os.path.join(workspace, '.'), '/src')
  ]
  result_code = helper.docker_run(command)
  if result_code:
    print('Building fuzzers failed.', file=sys.stderr)
    return result_code
  return 0


def run_fuzzers(args):
  """Runs a all fuzzer for a specific OSS-Fuzz project.

  Returns:
    True on success False on failure.
  """
  print('Starting to run fuzzers.')

  fuzzer_paths = utils.get_project_fuzz_targets(args.project_name)
  print('Fuzzer paths', str(fuzzer_paths))
  fuzz_targets = []
  for fuzzer in fuzzer_paths:
    fuzz_targets.append(fuzz_target.FuzzTarget(args.project_name, fuzzer, 20))
  print(fuzzer_paths)
  error_detected = False

  for target in fuzz_targets:
    print('Fuzzer {} started running.'.format(target.target_name))
    test_case, stack_trace = target.start()
    if not test_case or not stack_trace:
      logging.debug('Fuzzer {} finished running.'.format(target.target_name))
      print('Fuzzer {} finished running.'.format(target.target_name))
    else:
      error_detected = True
      print("Fuzzer {} Detected Error: {}".format(target.target_name,
                                                  stack_trace),
            file=sys.stderr)
      shutil.move(test_case, '/tmp/testcase')
      break
  return not error_detected


if __name__ == '__main__':
  main()
