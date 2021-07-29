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

import environment

DEFAULT_LANGUAGE = 'c++'
DEFAULT_SANITIZER = 'address'

# This module deals a lot with env variables. Many of these will be set by users
# and others beyond CIFuzz's control. Thus, you should be careful about using
# the environment.py helpers for getting env vars, since it can cause values
# that should be interpreted as strings to be returned as other types (bools or
# ints for example). The environment.py helpers should not be used for values
# that are supposed to be strings.


def _get_project_repo_owner_and_name():
  """Returns a tuple containing the project repo owner and the name of the
  repo."""
  # On GitHub this includes owner and repo name.
  repository = os.getenv('GITHUB_REPOSITORY', '')
  # Use os.path.split. When GITHUB_REPOSITORY just contains the name of the
  # repo, this will return a tuple containing an empty string and the repo name.
  # When GITHUB_REPOSITORY contains the repo owner followed by a slash and then
  # the repo name, it will return a tuple containing the owner and repo name.
  return os.path.split(repository)


def _get_pr_ref(event):
  if event == 'pull_request':
    return os.getenv('GITHUB_REF')
  return None


def _get_sanitizer():
  return os.getenv('SANITIZER', DEFAULT_SANITIZER).lower()


def _is_dry_run():
  """Returns True if configured to do a dry run."""
  return environment.get_bool('DRY_RUN', False)


def get_project_src_path(workspace, is_github):
  """Returns the manually checked out path of the project's source if specified
  or None. Returns the path relative to |workspace| if |is_github| since on
  github the checkout will be relative to there."""
  path = os.getenv('PROJECT_SRC_PATH')
  if not path:
    logging.debug('No PROJECT_SRC_PATH.')
    return path

  logging.debug('PROJECT_SRC_PATH set: %s.', path)
  if is_github:
    # On GitHub, they don't know the absolute path, it is relative to
    # |workspace|.
    return os.path.join(workspace, path)
  return path


def _get_language():
  """Returns the project language."""
  # Get language from environment. We took this approach because the convenience
  # given to OSS-Fuzz users by not making them specify the language again (and
  # getting it from the project.yaml) is outweighed by the complexity in
  # implementing this. A lot of the complexity comes from our unittests not
  # setting a proper projet at this point.
  return os.getenv('LANGUAGE', DEFAULT_LANGUAGE)


# pylint: disable=too-few-public-methods,too-many-instance-attributes


class BaseConfig:
  """Object containing constant configuration for CIFuzz."""

  class Platform(enum.Enum):
    """Enum representing the different platforms CIFuzz runs on."""
    EXTERNAL_GITHUB = 0  # Non-OSS-Fuzz on GitHub actions.
    INTERNAL_GITHUB = 1  # OSS-Fuzz on GitHub actions.
    INTERNAL_GENERIC_CI = 2  # OSS-Fuzz on any CI.
    EXTERNAL_GENERIC_CI = 3  # Non-OSS-Fuzz on any CI.

  def __init__(self):
    self.workspace = os.getenv('GITHUB_WORKSPACE')
    self.oss_fuzz_project_name = os.getenv('OSS_FUZZ_PROJECT_NAME')
    self.project_repo_owner, self.project_repo_name = (
        _get_project_repo_owner_and_name())

    # Check if failures should not be reported.
    self.dry_run = _is_dry_run()

    self.sanitizer = _get_sanitizer()
    # TODO(ochang): Error out if both oss_fuzz and build_integration_path is not
    # set.
    self.build_integration_path = os.getenv('BUILD_INTEGRATION_PATH')

    self.language = _get_language()
    event_path = os.getenv('GITHUB_EVENT_PATH')
    self.is_github = bool(event_path)
    logging.debug('Is github: %s.', self.is_github)
    self.low_disk_space = environment.get_bool('LOW_DISK_SPACE', False)

    self.github_token = os.environ.get('GITHUB_TOKEN')
    self.git_store_repo = os.environ.get('GIT_STORE_REPO')
    self.git_store_branch = os.environ.get('GIT_STORE_BRANCH')
    self.git_store_branch_coverage = os.environ.get('GIT_STORE_BRANCH_COVERAGE',
                                                    self.git_store_branch)

  @property
  def is_internal(self):
    """Returns True if this is an OSS-Fuzz project."""
    return bool(self.oss_fuzz_project_name)

  @property
  def platform(self):
    """Returns the platform CIFuzz is runnning on."""
    if not self.is_internal:
      if not self.is_github:
        return self.Platform.EXTERNAL_GENERIC_CI
      return self.Platform.EXTERNAL_GITHUB

    if self.is_github:
      return self.Platform.INTERNAL_GITHUB
    return self.Platform.INTERNAL_GENERIC_CI

  @property
  def is_coverage(self):
    """Returns True if this CIFuzz run (building fuzzers and running them) for
    generating a coverage report."""
    return self.sanitizer == 'coverage'


class RunFuzzersConfig(BaseConfig):
  """Class containing constant configuration for running fuzzers in CIFuzz."""

  RUN_FUZZERS_MODES = {'batch', 'ci', 'coverage'}

  def __init__(self):
    super().__init__()
    self.fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 600))
    self.run_fuzzers_mode = os.environ.get('RUN_FUZZERS_MODE', 'ci').lower()
    if self.is_coverage:
      self.run_fuzzers_mode = 'coverage'

    if self.run_fuzzers_mode not in self.RUN_FUZZERS_MODES:
      raise Exception(
          ('Invalid RUN_FUZZERS_MODE %s not one of allowed choices: %s.' %
           (self.run_fuzzers_mode, self.RUN_FUZZERS_MODES)))

    self.report_unreproducible_crashes = environment.get_bool(
        'REPORT_UNREPRODUCIBLE_CRASHES', False)


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
      self.pr_ref = f'refs/pull/{event_data["pull_request"]["number"]}/merge'
      logging.debug('pr_ref: %s', self.pr_ref)

    self.git_url = event_data['repository']['html_url']

  def __init__(self):
    """Get the configuration from CIFuzz from the environment. These variables
    are set by GitHub or the user."""
    # TODO(metzman): Some of this config is very CI-specific. Move it into the
    # CI class.
    super().__init__()
    self.commit_sha = os.getenv('GITHUB_SHA')
    event = os.getenv('GITHUB_EVENT_NAME')

    self.pr_ref = None
    self.git_url = None
    self.base_commit = None
    self._get_config_from_event_path(event)

    self.base_ref = os.getenv('GITHUB_BASE_REF')
    self.project_src_path = get_project_src_path(self.workspace, self.is_github)

    self.allowed_broken_targets_percentage = os.getenv(
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE')
    self.bad_build_check = environment.get_bool('BAD_BUILD_CHECK', True)
    self.keep_unaffected_fuzz_targets = environment.get_bool(
        'KEEP_UNAFFECTED_FUZZERS')


class Workspace:
  """Class representing the workspace directory."""

  def __init__(self, config):
    self.workspace = config.workspace

  def initialize_dir(self, directory):  # pylint: disable=no-self-use
    """Creates directory if it doesn't already exist, otherwise does nothing."""
    os.makedirs(directory, exist_ok=True)

  @property
  def out(self):
    """The out directory used for storing the fuzzer build built by
    build_fuzzers."""
    # Don't use 'out' because it needs to be used by artifacts.
    return os.path.join(self.workspace, 'build-out')

  @property
  def work(self):
    """The directory used as the work directory for the fuzzer build/run."""
    return os.path.join(self.workspace, 'work')

  @property
  def artifacts(self):
    """The directory used to store artifacts for download by CI-system users."""
    # This is hardcoded by a lot of clients, so we need to use this.
    return os.path.join(self.workspace, 'out', 'artifacts')

  @property
  def clusterfuzz_build(self):
    """The directory where builds from ClusterFuzz are stored."""
    return os.path.join(self.workspace, 'cifuzz-prev-build')

  @property
  def clusterfuzz_coverage(self):
    """The directory where builds from ClusterFuzz are stored."""
    return os.path.join(self.workspace, 'cifuzz-prev-coverage')

  @property
  def coverage_report(self):
    """The directory where coverage reports generated by cifuzz are put."""
    return os.path.join(self.workspace, 'cifuzz-coverage')

  @property
  def corpora(self):
    """The directory where corpora from ClusterFuzz are stored."""
    return os.path.join(self.workspace, 'cifuzz-corpus')
