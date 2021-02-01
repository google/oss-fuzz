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


def _get_project_repo_name():
  return os.path.basename(os.getenv('GITHUB_REPOSITORY', ''))


def _get_pr_ref(event):
  if event == 'pull_request':
    return os.getenv('GITHUB_REF')
  return None


def _get_sanitizer():
  return os.getenv('SANITIZER', 'address').lower()


def _get_project_name():
  # TODO(metzman): Remove OSS-Fuzz reference.
  return os.getenv('OSS_FUZZ_PROJECT_NAME')


def _is_dry_run():
  """Returns True if configured to do a dry run."""
  return os.getenv('DRY_RUN', 'false').lower() == 'true'


def get_project_src_path(workspace):
  """Returns the manually checked out path of the project's source if specified
  or None."""
  # TODO(metzman): Get rid of MANUAL_SRC_PATH when Skia switches to
  # PROJECT_SRC_PATH.
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


# pylint: disable=too-few-public-methods,too-many-instance-attributes


class BaseConfig:
  """Object containing constant configuration for CIFuzz."""

  class Platform(enum.Enum):
    """Enum representing the different platforms CIFuzz runs on."""
    EXTERNAL_GITHUB = 0  # Non-OSS-Fuzz on GitHub actions.
    INTERNAL_GITHUB = 1  # OSS-Fuzz on GitHub actions.
    INTERNAL_GENERIC_CI = 2  # OSS-Fuzz on any CI.

  def __init__(self):
    self.workspace = os.getenv('GITHUB_WORKSPACE')
    self.project_name = _get_project_name()
    # Check if failures should not be reported.
    self.dry_run = _is_dry_run()
    self.sanitizer = _get_sanitizer()
    self.build_integration_path = os.getenv('BUILD_INTEGRATION_PATH')
    event_path = os.getenv('GITHUB_EVENT_PATH')
    self.is_github = bool(event_path)
    logging.debug('Is github: %s.', self.is_github)

  @property
  def platform(self):
    """Returns the platform CIFuzz is runnning on."""
    if self.build_integration_path:
      return self.Platform.EXTERNAL_GITHUB
    if self.is_github:
      return self.Platform.INTERNAL_GITHUB
    return self.Platform.INTERNAL_GENERIC_CI


class RunFuzzersConfig(BaseConfig):
  """Class containing constant configuration for running fuzzers in CIFuzz."""

  RUN_FUZZERS_MODES = {'batch', 'ci'}

  def __init__(self):
    super().__init__()
    self.fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 600))
    self.run_fuzzers_mode = os.environ.get('RUN_FUZZERS_MODE', 'ci').lower()
    if self.run_fuzzers_mode not in self.RUN_FUZZERS_MODES:
      raise Exception(
          ('Invalid RUN_FUZZERS_MODE %s not one of allowed choices: %s.' %
           self.run_fuzzers_mode, self.RUN_FUZZERS_MODES))


class BuildFuzzersConfig(BaseConfig):
  """Class containing constant configuration for building fuzzers in CIFuzz."""

  def _get_config_from_event_path(self, event):
    event_path = os.getenv('GITHUB_EVENT_PATH')
    if not event_path:
      return
    with open(event_path, encoding='utf-8') as file_handle:
      event_data = json.load(file_handle)
    if event == 'push':
      self.base_commit = event_data['before']
      logging.debug('base_commit: %s', self.base_commit)
    else:
      self.pr_ref = 'refs/pull/{0}/merge'.format(
          event_data['pull_request']['number'])
      logging.debug('pr_ref: %s', self.pr_ref)

    self.git_url = event_data['repository']['ssh_url']

  def __init__(self):
    """Get the configuration from CIFuzz from the environment. These variables
    are set by GitHub or the user."""
    # TODO(metzman): Some of this config is very CI-specific. Move it into the
    # CI class.
    super().__init__()
    self.project_repo_name = _get_project_repo_name()
    self.commit_sha = os.getenv('GITHUB_SHA')
    event = os.getenv('GITHUB_EVENT_NAME')

    self.pr_ref = None
    self.git_url = None
    self.base_commit = None
    self._get_config_from_event_path(event)

    self.base_ref = os.getenv('GITHUB_BASE_REF')
    self.project_src_path = get_project_src_path(self.workspace)

    self.allowed_broken_targets_percentage = os.getenv(
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE')

    # TODO(metzman): Use better system for interpreting env vars. What if env
    # var is set to '0'?
    self.keep_unaffected_fuzz_targets = bool(
        os.getenv('KEEP_UNAFFECTED_FUZZERS'))
