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
"""Module for getting the configuration CIFuzz needs to run on prow."""
import logging
import os

import platform_config

# pylint: disable=too-few-public-methods


class PlatformConfig(platform_config.BasePlatformConfig):
  """CI environment for Prow."""

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or the current directory if not. Prow will run ClusterfuzzLite
    at the directory head for the repo."""
    project_src_path = os.getenv('PROJECT_SRC_PATH', os.getcwd())
    logging.debug('PROJECT_SRC_PATH: %s.', project_src_path)
    return project_src_path

  @property
  def workspace(self):
    """Returns the workspace."""
    # Let Prow user override workspace, but default to using artifacts dir
    return os.getenv('WORKSPACE', os.getenv('ARTIFACTS'))

  @property
  def base_ref(self):
    """Returns the base branch to diff against (pr fuzzing)."""
    return os.getenv('PULL_BASE_REF')

  @property
  def project_repo_name(self):
    """Returns the project repo name."""
    return os.getenv('REPO_NAME')

  @property
  def base_commit(self):
    """Returns the base commit to diff against (commit fuzzing)."""
    return os.getenv('PULL_BASE_SHA')

  @property
  def docker_in_docker(self):
    """Returns True if using Docker in Docker."""
    return True

  @property
  def filestore(self):
    """Returns the filestore used to store persistent data."""
    return os.environ.get('FILESTORE', 'gsutil')
