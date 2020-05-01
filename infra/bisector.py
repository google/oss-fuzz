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
"""Uses bisection to determine which commit a bug was introduced and fixed.
This module takes a high and a low commit SHA, a repo name, and a bug.
The module bisects the high and low commit SHA searching for the location
where the bug was introduced. It also looks for where the bug was fixed.
This is done with the following steps:


  NOTE: Needs to be run from root of the OSS-Fuzz source checkout.

  Typical usage example:
        python3 infra/bisector.py
          --old_commit 1e403e9259a1abedf108ab86f711ba52c907226d
          --new_commit f79be4f2330f4b89ea2f42e1c44ca998c59a0c0f
          --fuzz_target rules_fuzzer
          --project_name yara
          --testcase infra/yara_testcase
          --sanitizer address
"""

import argparse
import collections
import datetime
from distutils import spawn
import json
import logging
import os
import tempfile

import build_specified_commit
import helper
import repo_manager
import utils

Result = collections.namedtuple('Result', ['repo_url', 'commit'])


def main():
  """Finds the commit SHA where an error was initally introduced."""
  logging.getLogger().setLevel(logging.INFO)
  utils.chdir_to_root()
  parser = argparse.ArgumentParser(
      description='git bisection for finding introduction of bugs')

  parser.add_argument('--project_name',
                      help='The name of the project where the bug occurred.',
                      required=True)
  parser.add_argument('--new_commit',
                      help='The newest commit SHA to be bisected.',
                      required=True)
  parser.add_argument('--old_commit',
                      help='The oldest commit SHA to be bisected.')
  parser.add_argument('--fuzz_target',
                      help='The name of the fuzzer to be built.',
                      required=True)
  parser.add_argument('--test_case_path',
                      help='The path to test case.',
                      required=True)
  parser.add_argument('--engine',
                      help='The default is "libfuzzer".',
                      default='libfuzzer')
  parser.add_argument('--sanitizer',
                      default='address',
                      help='The default is "address".')
  parser.add_argument('--architecture', default='x86_64')
  args = parser.parse_args()

  build_data = build_specified_commit.BuildData(project_name=args.project_name,
                                                engine=args.engine,
                                                sanitizer=args.sanitizer,
                                                architecture=args.architecture)

  result = bisect(args.old_commit, args.new_commit, args.test_case_path,
                  args.fuzz_target, build_data)
  if not result.commit:
    logging.error('No error was found in commit range %s:%s', args.old_commit,
                  args.new_commit)
    return 1
  if result.commit == args.old_commit:
    logging.error(
        'Bisection Error: Both the first and the last commits in'
        'the given range have the same behavior, bisection is not possible. ')
    return 1
  print('Error was introduced at commit %s' % result.commit)
  return 0


def _load_base_builder_repo():
  """Get base-image digests."""
  gcloud_path = spawn.find_executable('gcloud')
  if not gcloud_path:
    logging.warning('gcloud not found in PATH.')
    return None

  result, _, _ = utils.execute([
      gcloud_path,
      'container',
      'images',
      'list-tags',
      'gcr.io/oss-fuzz-base/base-builder',
      '--format=json',
      '--sort-by=timestamp',
  ],
                               check_result=True)
  result = json.loads(result)

  repo = build_specified_commit.BaseBuilderRepo()
  for image in result:
    timestamp = datetime.datetime.fromisoformat(
        image['timestamp']['datetime']).astimezone(datetime.timezone.utc)
    repo.add_digest(timestamp, image['digest'])

  return repo


def _bisect(old_commit, new_commit, test_case_path, fuzz_target, build_data):  # pylint: disable=too-many-locals
  """Perform the bisect."""
  base_builder_repo = _load_base_builder_repo()

  with tempfile.TemporaryDirectory() as tmp_dir:
    repo_url, repo_path = build_specified_commit.detect_main_repo(
        build_data.project_name, commit=new_commit)
    if not repo_url or not repo_path:
      raise ValueError('Main git repo can not be determined.')

    # Copy /src from the built Docker container to ensure all dependencies
    # exist. This will be mounted when running them.
    host_src_dir = build_specified_commit.copy_src_from_docker(
        build_data.project_name, tmp_dir)

    bisect_repo_manager = repo_manager.BaseRepoManager(
        os.path.join(host_src_dir, os.path.basename(repo_path)))
    commit_list = bisect_repo_manager.get_commit_list(new_commit, old_commit)

    old_idx = len(commit_list) - 1
    new_idx = 0
    logging.info('Testing against new_commit (%s)', commit_list[new_idx])
    if not build_specified_commit.build_fuzzers_from_commit(
        commit_list[new_idx],
        bisect_repo_manager,
        host_src_dir,
        build_data,
        base_builder_repo=base_builder_repo):
      raise RuntimeError('Failed to build new_commit')

    expected_error_code = helper.reproduce_impl(build_data.project_name,
                                                fuzz_target, False, [], [],
                                                test_case_path)

    # Check if the error is persistent through the commit range
    if old_commit:
      logging.info('Testing against old_commit (%s)', commit_list[old_idx])
      if not build_specified_commit.build_fuzzers_from_commit(
          commit_list[old_idx],
          bisect_repo_manager,
          host_src_dir,
          build_data,
          base_builder_repo=base_builder_repo):
        raise RuntimeError('Failed to build old_commit')

      if expected_error_code == helper.reproduce_impl(build_data.project_name,
                                                      fuzz_target, False, [],
                                                      [], test_case_path):
        raise RuntimeError('old_commit had same result as new_commit')

    while old_idx - new_idx > 1:
      curr_idx = (old_idx + new_idx) // 2
      logging.info('Testing against %s (idx=%d)', commit_list[curr_idx],
                   curr_idx)
      if not build_specified_commit.build_fuzzers_from_commit(
          commit_list[curr_idx],
          bisect_repo_manager,
          host_src_dir,
          build_data,
          base_builder_repo=base_builder_repo):
        # Treat build failures as if we couldn't repo.
        # TODO(ochang): retry nearby commits?
        old_idx = curr_idx
        continue

      error_code = helper.reproduce_impl(build_data.project_name, fuzz_target,
                                         False, [], [], test_case_path)
      if expected_error_code == error_code:
        new_idx = curr_idx
      else:
        old_idx = curr_idx
    return Result(repo_url, commit_list[new_idx])


def bisect(old_commit, new_commit, test_case_path, fuzz_target, build_data):  # pylint: disable=too-many-locals
  """From a commit range, this function caluclates which introduced a
  specific error from a fuzz test_case_path.

  Args:
    old_commit: The oldest commit in the error regression range.
    new_commit: The newest commit in the error regression range.
    test_case_path: The file path of the test case that triggers the error
    fuzz_target: The name of the fuzzer to be tested.
    build_data: a class holding all of the input parameters for bisection.

  Returns:
    The commit SHA that introduced the error or None.

  Raises:
    ValueError: when a repo url can't be determine from the project.
  """
  result = _bisect(old_commit, new_commit, test_case_path, fuzz_target,
                   build_data)

  # Clean up projects/ as _bisect may have modified it.
  oss_fuzz_repo_manager = repo_manager.BaseRepoManager(helper.OSS_FUZZ_DIR)
  oss_fuzz_repo_manager.git(['reset', 'projects'])
  oss_fuzz_repo_manager.git(['checkout', 'projects'])
  oss_fuzz_repo_manager.git(['clean', '-fxd', 'projects'])

  return result


if __name__ == '__main__':
  main()
