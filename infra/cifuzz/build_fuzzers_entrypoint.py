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
import logs
import config_utils

# pylint: disable=c-extension-no-member
# pylint gets confused because of the relative import of cifuzz.

logs.init()


def build_fuzzers_entrypoint():
  """Builds OSS-Fuzz project's fuzzers for CI tools."""
  config = config_utils.BuildFuzzersConfig()

  if config.dry_run:
    # Sets the default return code on error to success.
    returncode = 0
  else:
    # The default return code when an error occurs.
    returncode = 1

  if not build_fuzzers.build_fuzzers(config):
    logging.error('Error building fuzzers for (commit: %s, pr_ref: %s).',
                  config.git_sha, config.pr_ref)
    return returncode

  return 0


def main():
  """Builds OSS-Fuzz project's fuzzers for CI tools.

  Note: The resulting fuzz target binaries of this build are placed in
  the directory: ${GITHUB_WORKSPACE}/out

  Returns:
    0 on success or nonzero on failure.
  """
  return build_fuzzers_entrypoint()


if __name__ == '__main__':
  sys.exit(main())
