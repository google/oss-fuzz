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
"""Module for getting the configuration CIFuzz needs to run."""

import logging
import enum
import os
import json


class Config:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
  """Object containing constant configuration for CIFuzz."""

  class Platform(enum.Enum):
    """Enum representing the different platforms CIFuzz runs on."""
    EXTERNAL_GITHUB = 0  # Non-OSS-Fuzz on GitHub actions.
    INTERNAL_GITHUB = 1  # OSS-Fuzz on GitHub actions.
    INTERNAL_GENERIC_CI = 2  # OSS-Fuzz on any CI.

  def __init__(self):
    """Get the configuration from CIFuzz from the environment. These variables
    are set by GitHub or the user."""
    self.project_name = os.getenv('OSS_FUZZ_PROJECT_NAME')
    self.project_repo_name = os.path.basename(os.getenv('GITHUB_REPOSITORY'))
    self.commit_sha = os.getenv('GITHUB_SHA')

    event = os.getenv('GITHUB_EVENT')
    if event == 'pull_request':
      self.pr_ref = os.getenv('GITHUB_REF')
    else:
      self.pr_ref = None

    # TODO(metzman): We check event name before calling get_before_commit,
    # because external users (skia) are using it. Change this.
    event_name = os.getenv('GITHUB_EVENT_NAME')

    if event == 'push' and event_name:
      self.base_commit = get_before_commit(event_name)
    else:
      self.base_commit = None

    self.workspace = os.getenv('GITHUB_WORKSPACE')
    self.project_src_path = get_project_src_path(self.workspace)
    self.sanitizer = os.getenv('SANITIZER', 'address').lower()
    self.build_integration_path = os.getenv('BUILD_INTEGRATION_PATH')
    self.allowed_broken_targets_percentage = os.getenv(
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE')
    # Check if failures should not be reported.
    self.dry_run = _is_dry_run()
    self.base_ref = os.getenv('GITHUB_BASE_REF')

  @property
  def platform(self):
    """Returns the platform CIFuzz is runnning on."""
    if self.build_integration_path and self.project_src_path:
      return self.Platform.EXTERNAL_GITHUB
    if self.project_src_path:
      return self.Platform.INTERNAL_GENERIC_CI
    return self.Platform.INTERNAL_GITHUB


def _is_dry_run():
  """Returns True if configured to do a dry run."""
  return os.getenv('DRY_RUN').lower() == 'true'


def get_before_commit(event_path):
  """Returns the PR ref from |event_path|."""
  with open(event_path, encoding='utf-8') as file_handle:
    event = json.load(file_handle)
  return event['before']


def get_project_src_path(workspace):
  """Returns the manually checked out path of the project's source if specified
  or None."""
  # TODO(metzman): Get rid of MANUAL_SRC_PATH when Skia switches to
  # project_src_path.
  path = os.getenv('PROJECT_SRC_PATH', os.getenv('MANUAL_SRC_PATH'))
  if not path:
    logging.debug('No PROJECT_SRC_PATH.')
    return path

  logging.debug('PROJECT_SRC_PATH set.')
  if os.path.isabs(path):
    return path

  # If |src| is not absolute, assume we are running in GitHub actions.
  # TODO(metzman): Don't make this assumption.
  return os.path.join(workspace, path)
