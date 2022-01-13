# Copyright 2022 Google LLC
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
"""Module for getting the configuration CIFuzz needs to run on GitLab."""
import logging
import os

import environment
import platform_config


class PlatformConfig(platform_config.BasePlatformConfig):
  """CI environment for GitLab."""

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.path.join(os.getenv('CI_BUILDS_DIR'), os.getenv('CI_JOB_ID'))

  @property
  def git_sha(self):
    """Returns the Git SHA to checkout and fuzz."""
    return os.getenv('CI_COMMIT_SHA')

  @property
  def project_src_path(self):
    """Returns the directory with the source of the project"""
    return os.getenv('CI_PROJECT_DIR')

  @property
  def token(self):
    """Returns the job token"""
    return os.getenv('CI_JOB_TOKEN')

  @property
  def project_repo_name(self):
    """Returns the project's name"""
    return os.getenv('CI_PROJECT_NAME')

  @property
  def base_commit(self):
    """Returns the previous commit sha for commit-fuzzing"""
    base_commit = None
    if os.getenv('CI_PIPELINE_SOURCE') == 'push':
      base_commit = os.getenv('CI_COMMIT_BEFORE_SHA')
    logging.debug('base_commit: %s.', base_commit)
    return base_commit

  @property
  def base_ref(self):
    """Returns the base commit sha for a merge request"""
    # Could also be CI_MERGE_REQUEST_TARGET_BRANCH_NAME.
    return os.getenv('CI_MERGE_REQUEST_DIFF_BASE_SHA')

  @property
  def artifacts_dir(self):
    """Gitlab: returns the directory to put artifacts"""
    return environment.get('CFL_ARTIFACTS_DIR', 'artifacts')

  @property
  def cache_dir(self):
    """Gitlab: returns the directory to use as cache"""
    return environment.get('CFL_CACHE_DIR', 'cache')
