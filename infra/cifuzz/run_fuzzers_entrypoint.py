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
"""Runs specific OSS-Fuzz project's fuzzers for CI tools."""
import logging
import sys

import config_utils
import run_fuzzers

# pylint: disable=c-extension-no-member
# pylint gets confused because of the relative import of cifuzz.

# TODO: Turn default logging to INFO when CIFuzz is stable.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def main():
  """Runs OSS-Fuzz project's fuzzers for CI tools.
  This is the entrypoint for the run_fuzzers github action.
  This action can be added to any OSS-Fuzz project's workflow that uses Github.

  NOTE: libFuzzer binaries must be located in the ${GITHUB_WORKSPACE}/out
  directory in order for this action to be used. This action will only fuzz the
  binaries that are located in that directory. It is recommended that you add
  the build_fuzzers action preceding this one.

  NOTE: Any crash report will be in the filepath:
  ${GITHUB_WORKSPACE}/out/testcase
  This can be used in parallel with the upload-artifact action to surface the
  logs.

  Required environment variables:
    FUZZ_SECONDS: The length of time in seconds that fuzzers are to be run.
    GITHUB_WORKSPACE: The shared volume directory where input artifacts are.
    DRY_RUN: If true, no failures will surface.
    OSS_FUZZ_PROJECT_NAME: The name of the relevant OSS-Fuzz project.
    SANITIZER: The sanitizer to use when running fuzzers.

  Returns:
    0 on success or 1 on failure.
  """
  config = config_utils.RunFuzzersConfig()
  # The default return code when an error occurs.
  returncode = 1
  if config.dry_run:
    # Sets the default return code on error to success.
    returncode = 0

  if not config.workspace:
    logging.error('This script needs to be run within Github actions.')
    return returncode

  # Run the specified project's fuzzers from the build.
  run_status, bug_found = run_fuzzers.run_fuzzers(config)
  if not run_status:
    logging.error('Error occurred while running in workspace %s.',
                  config.workspace)
    return returncode
  if bug_found:
    logging.info('Bug found.')
    if not config.dry_run:
      # Return 2 when a bug was found by a fuzzer causing the CI to fail.
      return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
