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

import config_utils
# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils

BASE_BUILDER_TAG = 'gcr.io/oss-fuzz-base/base-builder'
BASE_RUNNER_TAG = 'gcr.io/oss-fuzz-base/base-runner'
MSAN_LIBS_BUILDER_TAG = 'gcr.io/oss-fuzz-base/msan-libs-builder'
PROJECT_TAG_PREFIX = 'gcr.io/oss-fuzz/'

_DEFAULT_DOCKER_RUN_ARGS = [
    '--cap-add', 'SYS_PTRACE', '-e',
    'FUZZING_ENGINE=' + config_utils.DEFAULT_ENGINE, '-e',
    'ARCHITECTURE=' + config_utils.DEFAULT_ARCHITECTURE, '-e', 'CIFUZZ=True'
]

EXTERNAL_PROJECT_IMAGE = 'external-project'

_DEFAULT_DOCKER_RUN_COMMAND = [
    'docker',
    'run',
    '--rm',
    '--privileged',
]


def get_project_image_name(project):
  """Returns the name of the project builder image for |project_name|."""
  # TODO(ochang): We may need unique names to support parallel fuzzing.
  if project:
    return PROJECT_TAG_PREFIX + project

  return EXTERNAL_PROJECT_IMAGE


def delete_images(images):
  """Deletes |images|."""
  command = ['docker', 'rmi', '-f'] + images
  utils.execute(command)
  utils.execute(['docker', 'builder', 'prune', '-f'])


def get_base_docker_run_args(workspace,
                             sanitizer=config_utils.DEFAULT_SANITIZER,
                             language=config_utils.DEFAULT_LANGUAGE):
  """Returns arguments that should be passed to every invocation of 'docker
  run'."""
  docker_args = _DEFAULT_DOCKER_RUN_ARGS.copy()
  docker_args += [
      '-e', f'SANITIZER={sanitizer}', '-e', f'FUZZING_LANGUAGE={language}',
      '-e', 'OUT=' + workspace.out
  ]
  docker_container = utils.get_container_name()
  logging.info('Docker container: %s.', docker_container)
  if docker_container:
    # Don't map specific volumes if in a docker container, it breaks when
    # running a sibling container.
    docker_args += ['--volumes-from', docker_container]
  else:
    docker_args += _get_args_mapping_host_path_to_container(workspace.workspace)
  return docker_args, docker_container


def get_base_docker_run_command(workspace,
                                sanitizer=config_utils.DEFAULT_SANITIZER,
                                language=config_utils.DEFAULT_LANGUAGE):
  """Returns part of the command that should be used everytime 'docker run' is
  invoked."""
  docker_args, docker_container = get_base_docker_run_args(
      workspace, sanitizer, language)
  command = _DEFAULT_DOCKER_RUN_COMMAND.copy() + docker_args
  return command, docker_container


def _get_args_mapping_host_path_to_container(host_path, container_path=None):
  """Get arguments to docker run that will map |host_path| a path on the host to
  a path in the container. If |container_path| is specified, that path is mapped
  to. If not, then |host_path| is mapped to itself in the container."""
  # WARNING: Do not use this function when running in production (and
  # --volumes-from) is used for mapping volumes. It will break production.
  container_path = host_path if container_path is None else container_path
  return ['-v', f'{host_path}:{container_path}']
