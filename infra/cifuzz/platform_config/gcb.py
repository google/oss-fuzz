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
"""Module for getting the configuration CIFuzz needs to run on Github."""
import logging
import os

import platform_config


class PlatformConfig(platform_config.BasePlatformConfig):
  """CI environment for Google Cloud Build."""

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or the default."""
    project_src_path = os.getenv('PROJECT_SRC_PATH', '/workspace')
    logging.debug('PROJECT_SRC_PATH: %s.', project_src_path)
    return project_src_path

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('WORKSPACE', '/builder/home')

  @property
  def filestore(self):
    """Returns the filestore used to store persistent data."""
    return os.environ.get('FILESTORE', 'gsutil')
