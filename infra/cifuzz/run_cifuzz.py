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
"""Script for running CIFuzz end-to-end. This is meant to work outside any
docker image. This cannot depend on any CIFuzz code or third party packages."""
import os
import subprocess
import sys
import tempfile
import logging

INFRA_DIR = os.path.dirname(os.path.dirname(__file__))
DEFAULT_ENVS = [('DRY_RUN', '0'), ('SANITIZER', 'address')]
BASE_CIFUZZ_DOCKER_TAG = 'gcr.io/oss-fuzz-base'


def set_default_env_var_if_unset(env_var, default_value):
  """Sets the value of |env_var| in the environment to |default_value| if it was
  not already set."""
  if env_var not in os.environ:
    os.environ[env_var] = default_value


def docker_run(name, workspace, project_src_path):
  """Runs a CIFuzz docker container with |name|."""
  command = [
      'docker', 'run', '--name', name, '--rm', '-e', 'PROJECT_SRC_PATH', '-e',
      'OSS_FUZZ_PROJECT_NAME', '-e', 'WORKSPACE', '-e', 'REPOSITORY', '-e',
      'DRY_RUN', '-e', 'CI', '-e', 'SANITIZER', '-e', 'GIT_SHA', '-e',
      'FILESTORE', '-e', 'NO_CLUSTERFUZZ_DEPLOYMENT'
  ]
  if project_src_path:
    command += ['-v', f'{project_src_path}:{project_src_path}']
  command += [
      '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v',
      f'{workspace}:{workspace}', f'{BASE_CIFUZZ_DOCKER_TAG}/{name}'
  ]
  print('Running docker command:', command)
  subprocess.run(command, check=True)


def docker_build(image):
  """Builds the CIFuzz |image|. Only suitable for building CIFuzz images."""
  command = [
      'docker', 'build', '-t', f'{BASE_CIFUZZ_DOCKER_TAG}/{image}', '--file',
      f'{image}.Dockerfile', '.'
  ]
  subprocess.run(command, check=True, cwd=INFRA_DIR)


def main():
  """Builds and runs fuzzers using CIFuzz."""
  for env_var, default_value in DEFAULT_ENVS:
    set_default_env_var_if_unset(env_var, default_value)

  repository = os.getenv('REPOSITORY')
  assert repository

  project_src_path = os.getenv('PROJECT_SRC_PATH')

  with tempfile.TemporaryDirectory() as temp_dir:
    if 'WORKSPACE' not in os.environ:
      os.environ['WORKSPACE'] = temp_dir

    workspace = os.environ['WORKSPACE']

    docker_build('build_fuzzers')
    docker_run('build_fuzzers', workspace, project_src_path)
    docker_build('run_fuzzers')
    try:
      docker_run('run_fuzzers', workspace, project_src_path)
    except subprocess.CalledProcessError:
      logging.error('run_fuzzers failed.')
      return 1
    return 0


if __name__ == '__main__':
  sys.exit(main())
