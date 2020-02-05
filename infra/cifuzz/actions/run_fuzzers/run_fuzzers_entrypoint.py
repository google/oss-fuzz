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

# pylint: disable=wrong-import-position
# pylint: disable=import-error
sys.path.append(os.path.join(os.environ['OSS_FUZZ_ROOT'], 'infra', 'cifuzz'))
import cifuzz

# TODO: Turn default logging to INFO when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def main():
  """Runs OSS-Fuzz project's fuzzers for CI tools.
  This is the entrypoint for the run_fuzzers github action.
  This action can be added to any OSS-Fuzz project's workflow that uses Github.

  NOTE: libfuzzer binaries must be located in the ${GITHUB_WORKSPACE}/out
  directory in order for this action to be used. This action will only fuzz the
  binary's that are located in that directory. It is reccomended that you add
  the build_fuzzers action preceding this one.

  NOTE: Any crash report will be in the filepath:
  ${GITHUB_WORKSPACE}/out/testcase
  This can be used in parallel with the upload-artifact action to surface the
  logs.

  Required environment variables:
    PROJECT_NAME: The name of OSS-Fuzz project.
    FUZZ_SECONDS: The length of time in seconds that fuzzers are to be run.
    GITHUB_WORKSPACE: The shared volume directory where input artifacts are.
    DRY_RUN: If true, no failures will surface.

  Returns:
    0 on success or 1 on Failure.
  """
  oss_fuzz_project_name = os.environ.get('PROJECT_NAME')
  fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 360))
  workspace = os.environ.get('GITHUB_WORKSPACE')

  # Check if failures should not be reported.
  dry_run = (os.environ.get('DRY_RUN').lower() == 'true')

  # The default return code when an error occurs.
  error_code = 1
  if dry_run:
    # A testcase file is required in order for CIFuzz to surface bugs.
    # If the file does not exist, the action will crash attempting to upload it.
    # The dry run needs this file because it is set to upload a test case both
    # on successful runs and on failures.
    out_dir = os.path.join(workspace, 'out')
    os.makedirs(out_dir, exist_ok=True)
    file_handle = open(os.path.join(out_dir, 'testcase'), 'w')
    file_handle.write('No bugs detected.')
    file_handle.close()

    # Sets the default return code on error to success.
    error_code = 0

  if not workspace:
    logging.error('This script needs to be run in the Github action context.')
    return error_code
  # Run the specified project's fuzzers from the build.
  run_status, bug_found = cifuzz.run_fuzzers(oss_fuzz_project_name,
                                             fuzz_seconds, workspace)
  if not run_status:
    logging.error('Error occured while running fuzzers for project %s.',
                  oss_fuzz_project_name)
    return error_code
  if bug_found:
    logging.info('Bug found.')
    if not dry_run:
      # Return 2 when a bug was found by a fuzzer causing the CI to fail.
      return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
