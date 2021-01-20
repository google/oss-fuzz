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
"""Builds a specific OSS-Fuzz project's fuzzers for CI tools."""
import json
import logging
import os
import sys

import cifuzz

# TODO: Turn default logging to INFO when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def get_pr_ref(event_path):
  """Returns the PR ref from |event_path|."""
  with open(event_path, encoding='utf-8') as file_handle:
    event = json.load(file_handle)
    return 'refs/pull/{0}/merge'.format(event['pull_request']['number'])


def get_project_src_path(workspace):
  """Returns the manually checked out path of the project's source if specified
  or None."""
  # TODO(metzman): Get rid of MANUAL_SRC_PATH when Skia switches to
  # project_src_path.
  path = os.getenv('PROJECT_SRC_PATH', os.getenv('MANUAL_SRC_PATH'))
  if not path:
    logging.debug('No PROJECT_SRC_PATH.')
    return path

  logging.debug('PROJECT_SRC_PATH set.')
  if os.path.isabs(path):
    return path

  # If |src| is not absolute, assume we are running in GitHub actions.
  # TODO(metzman): Don't make this assumption.
  return os.path.join(workspace, path)


def main():
  """Build OSS-Fuzz project's fuzzers for CI tools.
  This script is used to kick off the Github Actions CI tool. It is the
  entrypoint of the Dockerfile in this directory. This action can be added to
  any OSS-Fuzz project's workflow that uses Github.

  Note: The resulting clusterfuzz binaries of this build are placed in
  the directory: ${GITHUB_WORKSPACE}/out

  Required environment variables:
    OSS_FUZZ_PROJECT_NAME: The name of OSS-Fuzz project.
    GITHUB_REPOSITORY: The name of the Github repo that called this script.
    GITHUB_SHA: The commit SHA that triggered this script.
    GITHUB_EVENT_NAME: The name of the hook event that triggered this script.
    GITHUB_EVENT_PATH:
      The path to the file containing the POST payload of the webhook:
      https://help.github.com/en/actions/reference/virtual-environments-for-github-hosted-runners#filesystems-on-github-hosted-runners
    GITHUB_WORKSPACE: The shared volume directory where input artifacts are.
    DRY_RUN: If true, no failures will surface.
    SANITIZER: The sanitizer to use when running fuzzers.

  Returns:
    0 on success or 1 on failure.
  """
  oss_fuzz_project_name = os.getenv('OSS_FUZZ_PROJECT_NAME')
  github_repo_name = os.path.basename(os.getenv('GITHUB_REPOSITORY'))
  commit_sha = os.getenv('GITHUB_SHA')
  event = os.getenv('GITHUB_EVENT_NAME')
  workspace = os.getenv('GITHUB_WORKSPACE')
  sanitizer = os.getenv('SANITIZER').lower()
  project_src_path = get_project_src_path(workspace)
  build_integration_path = os.getenv('BUILD_INTEGRATION_PATH')
  allowed_broken_targets_percentage = os.getenv(
      'ALLOWED_BROKEN_TARGETS_PERCENTAGE')

  # Check if failures should not be reported.
  dry_run = os.getenv('DRY_RUN').lower() == 'true'
  if dry_run:
    # Sets the default return code on error to success.
    returncode = 0
  else:
    # The default return code when an error occurs.
    returncode = 1

  if not workspace:
    logging.error('This script needs to be run within Github actions.')
    return returncode

  if event == 'pull_request':
    event_path = os.getenv('GITHUB_EVENT_PATH')
    pr_ref = get_pr_ref(event_path)
  else:
    pr_ref = None

  if not cifuzz.build_fuzzers(oss_fuzz_project_name,
                              github_repo_name,
                              workspace,
                              commit_sha=commit_sha,
                              pr_ref=pr_ref,
                              sanitizer=sanitizer,
                              project_src_path=project_src_path,
                              build_integration_path=build_integration_path):
    logging.error(
        'Error building fuzzers for project %s (commit: %s, pr_ref: %s).',
        oss_fuzz_project_name, commit_sha, pr_ref)
    return returncode

  out_dir = os.path.join(workspace, 'out')
  if cifuzz.check_fuzzer_build(
      out_dir,
      sanitizer=sanitizer,
      allowed_broken_targets_percentage=allowed_broken_targets_percentage):
    returncode = 0

  return returncode


if __name__ == '__main__':
  sys.exit(main())
