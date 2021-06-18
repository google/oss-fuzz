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
import os
import sys

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils

BASE_BUILDER_TAG = 'gcr.io/oss-fuzz-base/base-builder'
BASE_RUNNER_TAG = 'gcr.io/oss-fuzz-base/base-runner'
MSAN_LIBS_BUILDER_TAG = 'gcr.io/oss-fuzz-base/msan-libs-builder'
PROJECT_TAG_PREFIX = 'gcr.io/oss-fuzz/'


def get_project_image_name(project):
  """Returns the name of the project builder image for |project_name|."""
  return PROJECT_TAG_PREFIX + project


def delete_images(images):
  """Deletes |images|."""
  command = ['docker', 'rmi', '-f'] + images
  utils.execute(command)
  utils.execute(['docker', 'builder', 'prune', '-f'])


def get_args_mapping_host_path_to_container(path):
  """Get arguments to docker run that will map |path| a path on the host to the
  same location in the container."""
  return ['-v', f'{path}:{path}']
