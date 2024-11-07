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

import enum
import importlib
import logging
import os
import sys

import environment

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import platform_config
import constants

SANITIZERS = ['address', 'memory', 'undefined', 'coverage']

# TODO(metzman): Set these on config objects so there's one source of truth.
DEFAULT_ENGINE = 'libfuzzer'

# This module deals a lot with env variables. Many of these will be set by users
# and others beyond CIFuzz's control. Thus, you should be careful about using
# the environment.py helpers for getting env vars, since it can cause values
# that should be interpreted as strings to be returned as other types (bools or
# ints for example). The environment.py helpers should not be used for values
# that are supposed to be strings.


def _get_sanitizer():
  return os.getenv('SANITIZER', constants.DEFAULT_SANITIZER).lower()


def _get_architecture():
  return os.getenv('ARCHITECTURE', constants.DEFAULT_ARCHITECTURE).lower()


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


def _get_extra_environment_variables():
  """Gets extra environment variables specified by the user with
  CFL_EXTRA_$NAME=$VALUE."""
  return [key for key in os.environ if key.startswith('CFL_EXTRA_')]


# pylint: disable=too-many-instance-attributes


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

  @property
  def is_github(self):
    """Returns True if running on GitHub."""
    return self.cfl_platform == 'github'

  def __init__(self):
    # Need to set these before calling self.platform.
    self.oss_fuzz_project_name = os.getenv('OSS_FUZZ_PROJECT_NAME')
    self.cfl_platform = os.getenv('CFL_PLATFORM')
    logging.debug('Is github: %s.', self.is_github)

    self.platform_conf = _get_platform_config(self.cfl_platform)
    self.base_commit = self.platform_conf.base_commit
    self.base_ref = self.platform_conf.base_ref
    self.pr_ref = self.platform_conf.pr_ref
    self.workspace = self.platform_conf.workspace
    self.project_src_path = self.platform_conf.project_src_path
    self.actor = self.platform_conf.actor
    self.token = self.platform_conf.token
    self.project_repo_owner = self.platform_conf.project_repo_owner
    self.project_repo_name = self.platform_conf.project_repo_name
    self.filestore = self.platform_conf.filestore

    # This determines if builds are done using docker in docker
    # rather than the normal method which is sibling containers.
    self.docker_in_docker = self.platform_conf.docker_in_docker

    self.dry_run = _is_dry_run()  # Check if failures should not be reported.
    self.sanitizer = _get_sanitizer()
    self.architecture = _get_architecture()
    self.language = _get_language()
    self.low_disk_space = environment.get_bool('LOW_DISK_SPACE', False)

    self.git_store_repo = os.environ.get('GIT_STORE_REPO')
    self.git_store_branch = os.environ.get('GIT_STORE_BRANCH')
    self.git_store_branch_coverage = os.environ.get('GIT_STORE_BRANCH_COVERAGE',
                                                    self.git_store_branch)
    self.cloud_bucket = os.environ.get('CLOUD_BUCKET')
    self.no_clusterfuzz_deployment = environment.get_bool(
        'NO_CLUSTERFUZZ_DEPLOYMENT', False)
    self.build_integration_path = (
        constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH)

    self.parallel_fuzzing = environment.get_bool('PARALLEL_FUZZING', False)
    self.extra_environment_variables = _get_extra_environment_variables()
    self.output_sarif = environment.get_bool('OUTPUT_SARIF', False)

    # TODO(metzman): Fix tests to create valid configurations and get rid of
    # CIFUZZ_TEST here and in presubmit.py.
    if not os.getenv('CIFUZZ_TEST') and not self.validate():
      raise ConfigError('Invalid Configuration.')

  def validate(self):
    """Returns False if the configuration is invalid."""
    # Do validation here so that unittests don't need to make a fully-valid
    # config.
    # pylint: disable=too-many-return-statements
    if not self.workspace:
      logging.error('Must set WORKSPACE.')
      return False

    if self.sanitizer not in SANITIZERS:
      logging.error('Invalid SANITIZER: %s. Must be one of: %s.',
                    self.sanitizer, SANITIZERS)
      return False

    if self.architecture not in constants.ARCHITECTURES:
      logging.error('Invalid ARCHITECTURE: %s. Must be one of: %s.',
                    self.architecture, constants.ARCHITECTURES)
      return False

    if self.architecture == 'i386' and self.sanitizer != 'address':
      logging.error(
          'ARCHITECTURE=i386 can be used with SANITIZER=address only.')
      return False

    if self.language not in constants.LANGUAGES:
      logging.error('Invalid LANGUAGE: %s. Must be one of: %s.', self.language,
                    constants.LANGUAGES)
      return False

    if not self.project_repo_name:
      logging.error('Must set REPOSITORY.')
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


def _get_platform_config(cfl_platform):
  """Returns the CI environment object for |cfl_platform|."""
  module_name = f'platform_config.{cfl_platform}'
  try:
    cls = importlib.import_module(module_name).PlatformConfig
  except ImportError:
    cls = platform_config.BasePlatformConfig
  return cls()


class RunFuzzersConfig(BaseConfig):
  """Class containing constant configuration for running fuzzers in CIFuzz."""

  MODES = ['batch', 'code-change', 'coverage', 'prune']

  def __init__(self):
    super().__init__()
    # TODO(metzman): Pick a better default for pruning.
    self.fuzz_seconds = int(os.environ.get('FUZZ_SECONDS', 600))
    self.mode = os.environ.get('MODE', 'code-change').lower()
    if self.is_coverage:
      self.mode = 'coverage'

    self.report_unreproducible_crashes = environment.get_bool(
        'REPORT_UNREPRODUCIBLE_CRASHES', False)

    self.minimize_crashes = environment.get_bool('MINIMIZE_CRASHES', False)
    if self.mode == 'batch':
      logging.warning(
          'Minimizing crashes reduces fuzzing time in batch fuzzing.')
    self.report_timeouts = environment.get_bool('REPORT_TIMEOUTS', False)
    self.report_ooms = environment.get_bool('REPORT_OOMS', True)
    self.upload_all_crashes = environment.get_bool('UPLOAD_ALL_CRASHES', False)

    # TODO(metzman): Fix tests to create valid configurations and get rid of
    # CIFUZZ_TEST here and in presubmit.py.
    if not os.getenv('CIFUZZ_TEST') and not self._run_config_validate():
      raise ConfigError('Invalid Run Configuration.')

  def _run_config_validate(self):
    """Do extra validation on RunFuzzersConfig.__init__(). Do not name this
    validate or else it will be called when using the parent's __init__ and will
    fail. Returns True if valid."""
    if self.mode not in self.MODES:
      logging.error('Invalid MODE: %s. Must be one of %s.', self.mode,
                    self.MODES)
      return False

    return True


class BuildFuzzersConfig(BaseConfig):
  """Class containing constant configuration for building fuzzers in CIFuzz."""

  def __init__(self):
    """Get the configuration from CIFuzz from the environment. These variables
    are set by GitHub or the user."""
    super().__init__()
    self.git_sha = self.platform_conf.git_sha
    self.git_url = self.platform_conf.git_url

    self.allowed_broken_targets_percentage = os.getenv(
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE')
    self.bad_build_check = environment.get_bool('BAD_BUILD_CHECK', True)

    self.keep_unaffected_fuzz_targets = environment.get_bool(
        'KEEP_UNAFFECTED_FUZZ_TARGETS')

    self.upload_build = environment.get_bool('UPLOAD_BUILD', False)
    if not self.keep_unaffected_fuzz_targets:
      has_base_for_diff = (self.base_ref or self.base_commit)
      if not has_base_for_diff:
        logging.info(
            'Keeping all fuzzers because there is nothing to diff against.')
        self.keep_unaffected_fuzz_targets = True
      elif self.upload_build:
        logging.info('Keeping all fuzzers because we are uploading build.')
        self.keep_unaffected_fuzz_targets = True
      elif self.sanitizer == 'coverage':
        logging.info('Keeping all fuzzers because we are doing coverage.')
        self.keep_unaffected_fuzz_targets = True

    if self.sanitizer == 'coverage':
      self.bad_build_check = False
