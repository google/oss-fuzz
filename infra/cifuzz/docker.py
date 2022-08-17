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
import uuid

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constants
import utils
import environment

BASE_BUILDER_TAG = 'gcr.io/oss-fuzz-base/base-builder'
PROJECT_TAG_PREFIX = 'gcr.io/oss-fuzz/'

# Default fuzz configuration.
_DEFAULT_DOCKER_RUN_ARGS = [
    '-e', 'FUZZING_ENGINE=' + constants.DEFAULT_ENGINE, '-e', 'CIFUZZ=True'
]

UNIQUE_ID_SUFFIX = '-' + uuid.uuid4().hex

# TODO(metzman): Make run_fuzzers able to delete this image.
EXTERNAL_PROJECT_IMAGE = 'external-cfl-project' + UNIQUE_ID_SUFFIX

_DEFAULT_DOCKER_RUN_COMMAND = [
    'docker',
    'run',
    '--rm',
    '--privileged',
]


def get_docker_env_vars(env_mapping):
  """Returns a list of docker arguments that sets each key in |env_mapping| as
  an env var and the value of that key in |env_mapping| as the value."""
  env_var_args = []
  for env_var, env_var_val in env_mapping.items():
    env_var_args.extend(['-e', f'{env_var}={env_var_val}'])
  return env_var_args


def get_project_image_name(project):
  """Returns the name of the project builder image for |project_name|."""
  # TODO(jonathanmetzman): We may need unique names to support parallel fuzzing
  # for CIFuzz (like CFL supports). Don't do this for now because no one has
  # asked for it and build_specified_commit would need to be modified to support
  # this.
  if project:
    return PROJECT_TAG_PREFIX + project

  return EXTERNAL_PROJECT_IMAGE


def delete_images(images):
  """Deletes |images|."""
  command = ['docker', 'rmi', '-f'] + images
  utils.execute(command)
  utils.execute(['docker', 'builder', 'prune', '-f'])


def get_base_docker_run_args(workspace,
                             sanitizer=constants.DEFAULT_SANITIZER,
                             language=constants.DEFAULT_LANGUAGE,
                             architecture=constants.DEFAULT_ARCHITECTURE,
                             docker_in_docker=False):
  """Returns arguments that should be passed to every invocation of 'docker
  run'."""
  docker_args = _DEFAULT_DOCKER_RUN_ARGS.copy()
  env_mapping = {
      'SANITIZER': sanitizer,
      'ARCHITECTURE': architecture,
      'FUZZING_LANGUAGE': language,
      'OUT': workspace.out
  }
  docker_args += get_docker_env_vars(env_mapping)
  docker_container = environment.get('CFL_CONTAINER_ID',
                                     utils.get_container_name())
  logging.info('Docker container: %s.', docker_container)
  if docker_container and not docker_in_docker:
    # Don't map specific volumes if in a docker container, it breaks when
    # running a sibling container.
    docker_args += ['--volumes-from', docker_container]
  else:
    docker_args += _get_args_mapping_host_path_to_container(workspace.workspace)
  return docker_args, docker_container


def get_base_docker_run_command(workspace,
                                sanitizer=constants.DEFAULT_SANITIZER,
                                language=constants.DEFAULT_LANGUAGE,
                                architecture=constants.DEFAULT_ARCHITECTURE,
                                docker_in_docker=False):
  """Returns part of the command that should be used everytime 'docker run' is
  invoked."""
  docker_args, docker_container = get_base_docker_run_args(
      workspace,
      sanitizer,
      language,
      architecture,
      docker_in_docker=docker_in_docker)
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
