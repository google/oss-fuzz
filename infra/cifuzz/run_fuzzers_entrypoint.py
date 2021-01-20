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
import os
import sys

import cifuzz

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
  fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 600))
  workspace = os.environ.get('GITHUB_WORKSPACE')
  oss_fuzz_project_name = os.environ.get('OSS_FUZZ_PROJECT_NAME')
  sanitizer = os.environ.get('SANITIZER').lower()

  # Check if failures should not be reported.
  dry_run = (os.environ.get('DRY_RUN').lower() == 'true')

  # The default return code when an error occurs.
  returncode = 1
  if dry_run:
    # A testcase file is required in order for CIFuzz to surface bugs.
    # If the file does not exist, the action will crash attempting to upload it.
    # The dry run needs this file because it is set to upload a testcase both
    # on successful runs and on failures.
    out_dir = os.path.join(workspace, 'out', 'artifacts')
    os.makedirs(out_dir, exist_ok=True)

    # Sets the default return code on error to success.
    returncode = 0

  if not workspace:
    logging.error('This script needs to be run in the Github action context.')
    return returncode
  # Run the specified project's fuzzers from the build.
  run_status, bug_found = cifuzz.run_fuzzers(fuzz_seconds,
                                             workspace,
                                             oss_fuzz_project_name,
                                             sanitizer=sanitizer)
  if not run_status:
    logging.error('Error occurred while running in workspace %s.', workspace)
    return returncode
  if bug_found:
    logging.info('Bug found.')
    if not dry_run:
      # Return 2 when a bug was found by a fuzzer causing the CI to fail.
      return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
