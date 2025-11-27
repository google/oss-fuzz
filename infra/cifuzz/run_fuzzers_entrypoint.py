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
"""Runs a specific OSS-Fuzz project's fuzzers for CI tools."""
import logging
import os
import subprocess
import sys

import config_utils
import docker
import logs
import run_fuzzers

# pylint: disable=c-extension-no-member
# pylint gets confused because of the relative import of cifuzz.

logs.init()


def delete_unneeded_docker_images(config):
  """Deletes unneeded docker images if running in an environment with low
  disk space."""
  if not config.low_disk_space:
    return
  logging.info('Deleting builder docker images to save disk space.')
  project_image = docker.get_project_image_name(config.oss_fuzz_project_name)
  images = [
      project_image,
      docker.BASE_BUILDER_TAG,
      docker.BASE_BUILDER_TAG + '-go',
      docker.BASE_BUILDER_TAG + '-javascript',
      docker.BASE_BUILDER_TAG + '-jvm',
      docker.BASE_BUILDER_TAG + '-python',
      docker.BASE_BUILDER_TAG + '-rust',
      docker.BASE_BUILDER_TAG + '-ruby',
      docker.BASE_BUILDER_TAG + '-swift',
  ]
  docker.delete_images(images)


def run_fuzzers_entrypoint():
  """This is the entrypoint for the run_fuzzers github action.
  This action can be added to any OSS-Fuzz project's workflow that uses
  Github."""
  config = config_utils.RunFuzzersConfig()

  if config.base_os_version == 'ubuntu-24-04':
    with open('/etc/os-release') as file_handle:
      if 'Noble Numbat' not in file_handle.read():
        logging.info('Base OS version is Ubuntu 24.04, but running in a different OS. Pivoting to Ubuntu 24.04 container.')
        env = os.environ.copy()
        # Ensure we don't loop indefinitely.
        env['CIFUZZ_PIVOTED'] = '1'
        command = [
            'docker', 'run', '--rm', '--privileged',
            '--volumes-from', os.environ.get('HOSTNAME', ''),
            '-e', 'CIFUZZ_PIVOTED=1'
        ]
        # Propagate environment variables.
        for key, value in os.environ.items():
          command.extend(['-e', f'{key}={value}'])

        # Use the ubuntu-24-04 version of the run_fuzzers image.
        command.append('gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1-ubuntu-24-04')

        # Run the same command (run_fuzzers_entrypoint.py).
        command.append('python3')
        command.append('/opt/oss-fuzz/infra/cifuzz/run_fuzzers_entrypoint.py')

        try:
          subprocess.check_call(command)
        except subprocess.CalledProcessError as e:
          if not config.dry_run:
             return e.returncode
        return 0

  # The default return code when an error occurs.
  returncode = 1
  if config.dry_run:
    # Sets the default return code on error to success.
    returncode = 0

  delete_unneeded_docker_images(config)
  # Run the specified project's fuzzers from the build.
  result = run_fuzzers.run_fuzzers(config)
  if result == run_fuzzers.RunFuzzersResult.ERROR:
    logging.error('Error occurred while running in workspace %s.',
                  config.workspace)
    return returncode
  if result == run_fuzzers.RunFuzzersResult.BUG_FOUND:
    logging.info('Bug found.')
    if not config.dry_run:
      # Return 2 when a bug was found by a fuzzer causing the CI to fail.
      return 2
  return 0


def main():
  """Runs project's fuzzers for CI tools.
  This is the entrypoint for the run_fuzzers github action.

  NOTE: libFuzzer binaries must be located in the $WORKSPACE/build-out
  directory in order for this action to be used. This action will only fuzz the
  binaries that are located in that directory. It is recommended that you add
  the build_fuzzers action preceding this one.

  NOTE: Any crash report will be in the filepath:
  ${GITHUB_WORKSPACE}/out/testcase
  This can be used in parallel with the upload-artifact action to surface the
  logs.

  Returns:
    0 on success or nonzero on failure.
  """
  return run_fuzzers_entrypoint()


if __name__ == '__main__':
  sys.exit(main())
