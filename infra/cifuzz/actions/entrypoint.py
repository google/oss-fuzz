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
"""Builds and runs specific OSS-Fuzz project's fuzzers for CI tools."""
import logging
import os
import sys

# pylint: disable=wrong-import-position
sys.path.append(os.path.join(os.environ['OSS_FUZZ_ROOT'], 'infra', 'cifuzz'))
import cifuzz

# TODO: Turn default logging to INFO when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def main():
  """Runs OSS-Fuzz project's fuzzers for CI tools.
  This script is used to kick off the Github Actions CI tool. It is the
  entrypoint  of the Dockerfile in this directory. This action can be added to
  any OSS-Fuzz project's workflow that uses Github.

  Required environment variables:
    PROJECT_NAME: The name of OSS-Fuzz project.
    FUZZ_TIME: The length of time in seconds that fuzzers are to be run.
    GITHUB_REPOSITORY: The name of the Github repo that called this script.
    GITHUB_SHA: The commit SHA that triggered this script.
    GITHUB_REF: The pull request reference that triggered this script.
    GITHUB_EVENT_NAME: The name of the hook event that triggered this script.

  Returns:
    0 on success or 1 on Failure.
  """
  oss_fuzz_project_name = os.environ.get('PROJECT_NAME')
  fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 360))
  github_repo_name = os.path.basename(os.environ.get('GITHUB_REPOSITORY'))
  pr_ref = os.environ.get('GITHUB_REF')
  commit_sha = os.environ.get('GITHUB_SHA')
  event = os.environ.get('GITHUB_EVENT_NAME')

  # Get the shared volume directory and create required directorys.
  workspace = os.environ.get('GITHUB_WORKSPACE')
  if not workspace:
    logging.error('This script needs to be run in the Github action context.')
    return 1

  if event == 'push' and not cifuzz.build_fuzzers(
      oss_fuzz_project_name, github_repo_name, workspace,
      commit_sha=commit_sha):
    logging.error('Error building fuzzers for project %s with commit %s.',
                  oss_fuzz_project_name, commit_sha)
    return 1
  if event == 'pull_request' and not cifuzz.build_fuzzers(
      oss_fuzz_project_name, github_repo_name, workspace, pr_ref=pr_ref):
    logging.error('Error building fuzzers for project %s with pull request %s.',
                  oss_fuzz_project_name, pr_ref)
    return 1

  # Run the specified project's fuzzers from the build.
  run_status, bug_found = cifuzz.run_fuzzers(oss_fuzz_project_name,
                                             fuzz_seconds, workspace)
  if not run_status:
    logging.error('Error occured while running fuzzers for project %s.',
                  oss_fuzz_project_name)
    return 1
  if bug_found:
    logging.info('Bug found.')
    # Return 2 when a bug was found by a fuzzer causing the CI to fail.
    return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
