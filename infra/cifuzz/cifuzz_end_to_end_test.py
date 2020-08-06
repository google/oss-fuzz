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
"""End to end test that builds all cifuzz images and runs cifuzz on the
targets."""

import os
import tempfile
import unittest

import helper
import utils

CIFUZZ_PATH = os.path.join(helper.OSS_FUZZ_DIR, 'infra', 'cifuzz')


def run_docker_build(dockerfile, tag, path=None):
  """Runs docker build."""
  command = ['docker', 'build']
  if path:
    command.append(path)
  command.extend(['--file', dockerfile, '-t', tag])
  return utils.execute(command, check_result=True)


class EndToEndTest(unittest.TestCase):
  """End to end test for CIFuzz."""
  container_env_vars = {
      'OSS_FUZZ_PROJECT_NAME': 'systemd',
      'GITHUB_REPOSITORY': 'systemd',
      'GITHUB_EVENT_NAME': 'push',
      'DRY_RUN': '0',
      'ALLOWED_BROKEN_TARGETS_PERCENTAGE': '0',
      'GITHUB_ACTIONS': 'true',
      'CI': 'true',
      'GITHUB_SHA': '22e705b3073cc8d8e20039fde2143ac89df919be',
      'SANITIZER': 'address',
  }

  def run_cifuzz_container(self, name, workspace):
    """Runs the build_fuzzers or run_fuzzers container."""
    command = ['docker', 'run', '--name', name, '--rm']
    container_env_vars = self.container_env_vars.copy()
    container_env_vars['GITHUB_WORKSPACE'] = workspace
    for var, value in container_env_vars.items():
      command += ['-e', '{var}={value}'.format(var=var, value=value)]

    command += [
        '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v',
        '{workspace}:{workspace}'.format(workspace=workspace), name
    ]
    return utils.execute(command, check_result=True)

  def _test_end_to_end(self, tmp_dir):
    """Do the end-to-end test."""
    cifuzz_base_dockerfile = os.path.join(CIFUZZ_PATH, 'cifuzz-base',
                                          'Dockerfile')
    run_docker_build(cifuzz_base_dockerfile,
                     'gcr.io/oss-fuzz-base/cifuzz-base:latest', '.')

    # Build build_fuzzers and run_fuzzers
    for name in ['build_fuzzers', 'run_fuzzers']:
      path = os.path.join(CIFUZZ_PATH, 'actions', name)
      dockerfile = os.path.join(path, 'Dockerfile')
      run_docker_build(dockerfile, name, path)
      self.run_cifuzz_container(name, tmp_dir)

  def test_end_to_end(self):
    """Do the end-to-end test."""
    cwd = os.getcwd()
    try:
      utils.chdir_to_root()
      with tempfile.TemporaryDirectory() as tmp_dir:
        self._test_end_to_end(tmp_dir)
    finally:
      os.chdir(cwd)
