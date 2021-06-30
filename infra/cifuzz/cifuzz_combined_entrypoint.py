# Copyright 2021 Google LLC
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
"""Builds fuzzers and runs fuzzers. Entrypoint used for external users"""
import logging
import sys

import build_fuzzers_entrypoint
import run_fuzzers_entrypoint


def main():
  """Builds and runs fuzzers for CI tools.

  NOTE: Any crash report will be in the filepath:
  ${GITHUB_WORKSPACE}/out/testcase
 This can be used with GitHub's upload-artifact action to surface the logs.

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
    FUZZ_SECONDS: The length of time in seconds that fuzzers are to be run.

  Returns:
    0 on success or 1 on failure.
  """
  logging.debug("Using cifuzz_combined_entrypoint.")
  result = build_fuzzers_entrypoint.build_fuzzers_entrypoint()
  if result != 0:
    return result
  return run_fuzzers_entrypoint.run_fuzzers_entrypoint()


if __name__ == '__main__':
  sys.exit(main())
