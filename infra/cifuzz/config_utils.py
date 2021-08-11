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
import sys
import json

import environment

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constants

RUN_FUZZERS_MODES = ['batch', 'ci', 'coverage', 'prune']
SANITIZERS = ['address', 'memory', 'undefined', 'coverage']

# TODO(metzman): Set these on config objects so there's one source of truth.
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_ARCHITECTURE = 'x86_64'

# This module deals a lot with env variables. Many of these will be set by users
# and others beyond CIFuzz's control. Thus, you should be careful about using
# the environment.py helpers for getting env vars, since it can cause values
# that should be interpreted as strings to be returned as other types (bools or
# ints for example). The environment.py helpers should not be used for values
# that are supposed to be strings.


def _get_pr_ref(event):
  if event == 'pull_request':
    return os.getenv('GITHUB_REF')
  return None


def _get_sanitizer():
  return os.getenv('SANITIZER', constants.DEFAULT_SANITIZER).lower()


def _is_dry_run():
  """Returns True if configured to do a dry run."""
  return environment.get_bool('DRY_RUN', False)


def _get_language():
  """Returns the project language."""
  # Get language from environment. We took this approach because the convenience
  # given to OSS-Fuzz users by not making them specify the language again (and
  # getting it from the project.yaml) is outweighed by the complexity in
  # implementing this. A lot of the complexity comes from our unittests not
  # setting a proper projet at this point.
  return os.getenv('LANGUAGE', constants.DEFAULT_LANGUAGE)


# pylint: disable=too-few-public-methods,too-many-instance-attributes


class BaseCiEnvironment:
  """Base class for CiEnvironment subclasses."""

  @property
  def workspace(self):
    """Returns the workspace."""
    raise NotImplementedError('Child class must implment method.')

  @property
  def git_sha(self):
    """Returns the Git SHA to diff against."""
    raise NotImplementedError('Child class must implment method.')

  @property
  def token(self):
    """Returns the CI API token."""
    raise NotImplementedError('Child class must implment method.')

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or None."""

    path = os.getenv('PROJECT_SRC_PATH')
    if not path:
      logging.debug('No PROJECT_SRC_PATH.')
      return path

    logging.debug('PROJECT_SRC_PATH set: %s.', path)
    return path


class GenericCiEnvironment(BaseCiEnvironment):
  """CI Environment for generic CI systems."""

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('WORKSPACE')

  @property
  def git_sha(self):
    """Returns the Git SHA to diff against."""
    return os.getenv('GIT_SHA')

  @property
  def token(self):
    """Returns the CI API token."""
    return os.getenv('TOKEN')

  @property
  def project_repo_owner_and_name(self):
    """Returns a tuple containing the project repo owner and None."""
    repository = os.getenv('REPOSITORY')
    # Repo owner is a githubism.
    return None, repository


class GithubEnvironment(BaseCiEnvironment):
  """CI environment for GitHub."""

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('GITHUB_WORKSPACE')

  @property
  def git_sha(self):
    """Returns the Git SHA to diff against."""
    return os.getenv('GITHUB_SHA')

  @property
  def token(self):
    """Returns the CI API token."""
    return os.getenv('GITHUB_TOKEN')

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or None. The path returned is relative to |self.workspace| since
    on github the checkout will be relative to there."""
    # On GitHub, they don't know the absolute path, it is relative to
    # |workspace|.
    project_src_path = super().project_src_path
    if project_src_path is None:
      return project_src_path
    return os.path.join(self.workspace, project_src_path)

  @property
  def project_repo_owner_and_name(self):
    """Returns a tuple containing the project repo owner and the name of the
    repo."""
    # On GitHub this includes owner and repo name.
    repository = os.getenv('GITHUB_REPOSITORY')
    # Use os.path.split to split owner from repo.
    return os.path.split(repository)


class ConfigError(Exception):
  """Error for invalid configuration."""


class BaseConfig:
  """Object containing constant configuration for CIFuzz."""

  class Platform(enum.Enum):
    """Enum representing the different platforms CIFuzz runs on."""
    EXTERNAL_GITHUB = 0  # Non-OSS-Fuzz on GitHub actions.
    INTERNAL_GITHUB = 1  # OSS-Fuzz on GitHub actions.
    INTERNAL_GENERIC_CI = 2  # OSS-Fuzz on any CI.
    EXTERNAL_GENERIC_CI = 3  # Non-OSS-Fuzz on any CI.

  def __init__(self):
    # Need to set these before calling self.platform.
    self._github_event_path = os.getenv('GITHUB_EVENT_PATH')
    self.is_github = bool(self._github_event_path)
    logging.debug('Is github: %s.', self.is_github)
    self.oss_fuzz_project_name = os.getenv('OSS_FUZZ_PROJECT_NAME')

    self._ci_env = _get_ci_environment(self.platform)
    self.workspace = self._ci_env.workspace

    self.project_repo_owner, self.project_repo_name = (
        self._ci_env.project_repo_owner_and_name)

    # Check if failures should not be reported.
    self.dry_run = _is_dry_run()

    self.sanitizer = _get_sanitizer()

    self.build_integration_path = (
        constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH)
    self.language = _get_language()
    self.low_disk_space = environment.get_bool('LOW_DISK_SPACE', False)

    self.token = self._ci_env.token
    self.git_store_repo = os.environ.get('GIT_STORE_REPO')
    self.git_store_branch = os.environ.get('GIT_STORE_BRANCH')
    self.git_store_branch_coverage = os.environ.get('GIT_STORE_BRANCH_COVERAGE',
                                                    self.git_store_branch)

    # TODO(metzman): Fix tests to create valid configurations and get rid of
    # CIFUZZ_TEST here and in presubmit.py.
    if not os.getenv('CIFUZZ_TEST') and not self.validate():
      raise ConfigError('Invalid Configuration.')

  def validate(self):
    """Returns False if the configuration is invalid."""
    # Do validation here so that unittests don't need to make a fully-valid
    # config.
    if not self.workspace:
      logging.error('Must set WORKSPACE.')
      return False

    if self.sanitizer not in SANITIZERS:
      logging.error('Invalid SANITIZER: %s. Must be one of: %s.',
                    self.sanitizer, SANITIZERS)
      return False

    if self.language not in constants.LANGUAGES:
      logging.error('Invalid LANGUAGE: %s. Must be one of: %s.', self.language,
                    constants.LANGUAGES)
      return False

    return True

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


_CI_ENVIRONMENT_MAPPING = {
    BaseConfig.Platform.EXTERNAL_GITHUB: GithubEnvironment,
    BaseConfig.Platform.INTERNAL_GITHUB: GithubEnvironment,
    BaseConfig.Platform.INTERNAL_GENERIC_CI: GenericCiEnvironment,
    BaseConfig.Platform.EXTERNAL_GENERIC_CI: GenericCiEnvironment,
}


def _get_ci_environment(platform):
  """Returns the CI environment object for |platform|."""
  return _CI_ENVIRONMENT_MAPPING[platform]()


class RunFuzzersConfig(BaseConfig):
  """Class containing constant configuration for running fuzzers in CIFuzz."""

  def __init__(self):
    super().__init__()
    # TODO(metzman): Pick a better default for pruning.
    self.fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 600))
    self.run_fuzzers_mode = os.environ.get('RUN_FUZZERS_MODE', 'ci').lower()
    if self.is_coverage:
      self.run_fuzzers_mode = 'coverage'

    self.report_unreproducible_crashes = environment.get_bool(
        'REPORT_UNREPRODUCIBLE_CRASHES', False)

    # TODO(metzman): Fix tests to create valid configurations and get rid of
    # CIFUZZ_TEST here and in presubmit.py.
    if not os.getenv('CIFUZZ_TEST') and not self._run_config_validate():
      raise ConfigError('Invalid Run Configuration.')

  def _run_config_validate(self):
    """Do extra validation on RunFuzzersConfig.__init__(). Do not name this
    validate or else it will be called when using the parent's __init__ and will
    fail. Returns True if valid."""
    if self.run_fuzzers_mode not in RUN_FUZZERS_MODES:
      logging.error('Invalid RUN_FUZZERS_MODE: %s. Must be one of %s.',
                    self.run_fuzzers_mode, RUN_FUZZERS_MODES)
      return False

    return True


class BuildFuzzersConfig(BaseConfig):
  """Class containing constant configuration for building fuzzers in CIFuzz."""

  def _get_config_from_event_path(self, event):
    if not self._github_event_path:
      return
    with open(self._github_event_path, encoding='utf-8') as file_handle:
      event_data = json.load(file_handle)
    if event == 'push':
      self.base_commit = event_data['before']
      logging.debug('base_commit: %s', self.base_commit)
    elif event == 'pull_request':
      self.pr_ref = f'refs/pull/{event_data["pull_request"]["number"]}/merge'
      logging.debug('pr_ref: %s', self.pr_ref)

    self.git_url = event_data['repository']['html_url']

  def __init__(self):
    """Get the configuration from CIFuzz from the environment. These variables
    are set by GitHub or the user."""
    super().__init__()
    self.commit_sha = self._ci_env.git_sha
    event = os.getenv('GITHUB_EVENT_NAME')

    self.pr_ref = None
    self.git_url = None
    self.base_commit = None
    self._get_config_from_event_path(event)

    self.base_ref = os.getenv('GITHUB_BASE_REF')
    self.project_src_path = self._ci_env.project_src_path

    self.allowed_broken_targets_percentage = os.getenv(
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE')
    self.bad_build_check = environment.get_bool('BAD_BUILD_CHECK', True)
    # pylint: disable=consider-using-ternary
    self.keep_unaffected_fuzz_targets = (
        # Not from a commit or PR.
        (not self.base_ref and not self.base_commit) or
        environment.get_bool('KEEP_UNAFFECTED_FUZZERS'))
