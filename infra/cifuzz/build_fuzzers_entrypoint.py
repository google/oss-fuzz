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
import logging
import sys

import build_fuzzers
import config_utils
import docker

# pylint: disable=c-extension-no-member
# pylint gets confused because of the relative import of cifuzz.

# TODO: Turn default logging to INFO when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


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
  config = config_utils.BuildFuzzersConfig()

  if config.dry_run:
    # Sets the default return code on error to success.
    returncode = 0
  else:
    # The default return code when an error occurs.
    returncode = 1

  if not config.workspace:
    logging.error('This script needs to be run within Github actions.')
    return returncode

  if not build_fuzzers.build_fuzzers(config):
    logging.error(
        'Error building fuzzers for project %s (commit: %s, pr_ref: %s).',
        config.project_name, config.commit_sha, config.pr_ref)
    return returncode

  if not config.bad_build_check:
    # If we've gotten to this point and we don't need to do bad_build_check,
    # then the build has succeeded.
    returncode = 0
  # yapf: disable
  elif build_fuzzers.check_fuzzer_build(
      docker.Workspace(config),
      config.sanitizer,
      config.language,
      allowed_broken_targets_percentage=config.allowed_broken_targets_percentage
  ):
    # yapf: enable
    returncode = 0

  return returncode


if __name__ == '__main__':
  sys.exit(main())
