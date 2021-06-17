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
"""Module for dealing with docker."""
import logging
import os
import sys

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils

BASE_BUILDER_TAG = 'gcr.io/oss-fuzz-base/base-builder'
BASE_RUNNER_TAG = 'gcr.io/oss-fuzz-base/base-runner'
MSAN_LIBS_BUILDER_TAG = 'gcr.io/oss-fuzz-base/msan-libs-builder'
PROJECT_TAG_PREFIX = 'gcr.io/oss-fuzz/'

# Default fuzz configuration.
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_ARCHITECTURE = 'x86_64'
_DEFAULT_DOCKER_RUN_ARGS = [
    '-e', 'FUZZING_ENGINE=' + DEFAULT_ENGINE, '-e',
    'ARCHITECTURE=' + DEFAULT_ARCHITECTURE, '-e', 'CIFUZZ=True'
]

_DEFAULT_DOCKER_RUN_COMMAND = [
    'docker',
    'run',
    '--rm',
    '--privileged',
    '--cap-add',
    'SYS_PTRACE',
]


def get_project_image_name(project):
  """Returns the name of the project builder image for |project_name|."""
  return PROJECT_TAG_PREFIX + project


def delete_images(images):
  """Deletes |images|."""
  command = ['docker', 'rmi', '-f'] + images
  utils.execute(command)
  utils.execute(['docker', 'builder', 'prune', '-f'])


def get_base_docker_run_args(out_dir, sanitzer='address', language='c++'):
  # !!!
  docker_args = _DEFAULT_DOCKER_RUN_ARGS[:]
  docker_args += [
      '-e', f'SANITIZER={sanitizer}', '-e', f'FUZZING_LANGUAGE={language}',
  ]
  docker_container = utils.get_container_name()
  if docker_container:
    docker_args += ['--volumes-from', docker_container, '-e', 'OUT=' + out_dir]
  else:
    docker_args += ['-v', f'{out_dir}:/out']
  return docker_args, docker_container


def get_base_docker_run_command(out_dir, sanitzer='address', language='c++'):
  command = DOCKER_RUN_COMMAND[:]
  docker_args, docker_container = get_base_docker_run_args(
      out_dir, sanitizer, language)
  command += docker_args
  return command, docker_container
