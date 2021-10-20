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
import os
import unittest
from unittest import mock

import config_utils
import constants
import test_helpers

# pylint: disable=no-self-use,protected-access


class BaseConfigTest(unittest.TestCase):
  """Tests for BaseConfig."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def _create_config(self):
    return config_utils.BuildFuzzersConfig()

  def test_language_default(self):
    """Tests that the correct default language is set."""
    config = self._create_config()
    self.assertEqual(config.language, 'c++')

  def test_language(self):
    """Tests that the correct language is set."""
    language = 'python'
    os.environ['LANGUAGE'] = language
    config = self._create_config()
    self.assertEqual(config.language, language)

  def test_is_coverage(self):
    """Tests that is_coverage is set correctly."""
    # Test it is set when it is supposed to be.
    os.environ['SANITIZER'] = 'coverage'
    config = self._create_config()
    self.assertTrue(config.is_coverage)

    # Test it is not set when it is not supposed to be.
    os.environ['SANITIZER'] = 'address'
    config = self._create_config()
    self.assertFalse(config.is_coverage)

  @mock.patch('logging.error')
  def test_validate_no_workspace(self, mock_error):
    """Tests that validate returns False if GITHUB_WORKSPACE isn't set."""
    os.environ['OSS_FUZZ_PROJECT_NAME'] = 'example'
    config = self._create_config()
    self.assertFalse(config.validate())
    mock_error.assert_called_with('Must set WORKSPACE.')

  @mock.patch('logging.error')
  def test_validate_invalid_language(self, mock_error):
    """Tests that validate returns False if GITHUB_WORKSPACE isn't set."""
    os.environ['OSS_FUZZ_PROJECT_NAME'] = 'example'
    os.environ['WORKSPACE'] = '/workspace'
    os.environ['LANGUAGE'] = 'invalid-language'
    config = self._create_config()
    self.assertFalse(config.validate())
    mock_error.assert_called_with('Invalid LANGUAGE: %s. Must be one of: %s.',
                                  os.environ['LANGUAGE'], constants.LANGUAGES)

  @mock.patch('logging.error')
  def test_validate_invalid_sanitizer(self, mock_error):
    """Tests that validate returns False if GITHUB_WORKSPACE isn't set."""
    os.environ['OSS_FUZZ_PROJECT_NAME'] = 'example'
    os.environ['WORKSPACE'] = '/workspace'
    os.environ['SANITIZER'] = 'invalid-sanitizer'
    config = self._create_config()
    self.assertFalse(config.validate())
    mock_error.assert_called_with('Invalid SANITIZER: %s. Must be one of: %s.',
                                  os.environ['SANITIZER'],
                                  config_utils.SANITIZERS)

  def test_validate(self):
    """Tests that validate returns True if config is valid."""
    os.environ['OSS_FUZZ_PROJECT_NAME'] = 'example'
    os.environ['WORKSPACE'] = '/workspace'
    config = self._create_config()
    self.assertTrue(config.validate())


class BuildFuzzersConfigTest(unittest.TestCase):
  """Tests for BuildFuzzersConfig."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def _create_config(self):
    return config_utils.BuildFuzzersConfig()

  def test_base_ref(self):
    """Tests that base_ref is set properly."""
    expected_base_ref = 'expected_base_ref'
    os.environ['GITHUB_BASE_REF'] = expected_base_ref
    config = self._create_config()
    self.assertEqual(config.base_ref, expected_base_ref)

  def test_keep_unaffected_defaults_to_true(self):
    """Tests that keep_unaffected_fuzz_targets defaults to true."""
    config = self._create_config()
    self.assertTrue(config.keep_unaffected_fuzz_targets)

  def test_keep_unaffected_defaults_to_false_when_pr(self):
    """Tests that keep_unaffected_fuzz_targets defaults to false when from a
    pr."""
    os.environ['GITHUB_BASE_REF'] = 'base-ref'
    config = self._create_config()
    self.assertFalse(config.keep_unaffected_fuzz_targets)


class RunFuzzersConfigTest(unittest.TestCase):
  """Tests for RunFuzzersConfig."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def _create_config(self):
    return config_utils.RunFuzzersConfig()

  def test_coverage(self):
    """Tests that run_fuzzers_mode is overriden properly based on
    is_coverage."""
    # Test that it is overriden when it is supposed to be.
    os.environ['SANITIZER'] = 'coverage'
    os.environ['RUN_FUZZERS_MODE'] = 'code-change'
    config = self._create_config()
    self.assertEqual(config.run_fuzzers_mode, 'coverage')

    # Test that it isn't overriden when it isn't supposed to be.
    os.environ['SANITIZER'] = 'address'
    run_fuzzers_mode = 'code-change'
    os.environ['RUN_FUZZERS_MODE'] = run_fuzzers_mode
    config = self._create_config()
    self.assertEqual(config.run_fuzzers_mode, run_fuzzers_mode)

  def test_run_config_validate(self):
    """Tests that _run_config_validate returns True when the config is valid."""
    self.assertTrue(self._create_config()._run_config_validate())

  @mock.patch('logging.error')
  def test_run_config_invalid_mode(self, mock_error):
    """Tests that _run_config_validate returns False when run_fuzzers_mode is
    invalid."""
    fake_mode = 'fake-mode'
    os.environ['RUN_FUZZERS_MODE'] = fake_mode
    self.assertFalse(self._create_config()._run_config_validate())
    mock_error.assert_called_with(
        'Invalid RUN_FUZZERS_MODE: %s. Must be one of %s.', fake_mode,
        config_utils.RUN_FUZZERS_MODES)


class GetProjectRepoOwnerAndNameTest(unittest.TestCase):
  """Tests for BaseCiEnv.get_project_repo_owner_and_name."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.repo_owner = 'repo-owner'
    self.repo_name = 'repo-name'
    self.github_env = config_utils.GithubEnvironment()
    self.generic_ci_env = config_utils.GenericCiEnvironment()

  def test_unset_repository(self):
    """Tests that the correct result is returned when repository is not set."""
    self.assertEqual(self.generic_ci_env.project_repo_owner_and_name,
                     (None, None))

  def test_empty_repository(self):
    """Tests that the correct result is returned when repository is an empty
    string."""
    os.environ['REPOSITORY'] = ''
    self.assertEqual(self.generic_ci_env.project_repo_owner_and_name,
                     (None, ''))

  def test_github_repository(self):
    """Tests that the correct result is returned when repository contains the
    owner and repo name (as it does on GitHub)."""
    os.environ['GITHUB_REPOSITORY'] = f'{self.repo_owner}/{self.repo_name}'
    self.assertEqual(self.github_env.project_repo_owner_and_name,
                     (self.repo_owner, self.repo_name))

  def test_nongithub_repository(self):
    """Tests that the correct result is returned when repository contains the
    just the repo name (as it does outside of GitHub)."""
    os.environ['REPOSITORY'] = self.repo_name
    self.assertEqual(self.generic_ci_env.project_repo_owner_and_name,
                     (None, self.repo_name))


class GetRepoUrlTest(unittest.TestCase):
  """Tests for GenericCiEnvironment.repo_url."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.github_env = config_utils.GithubEnvironment()
    self.generic_ci_env = config_utils.GenericCiEnvironment()

  def test_unset_repository(self):
    """Tests that the correct result is returned when repository is not set."""
    self.assertEqual(self.generic_ci_env.repo_url, None)

  def test_github_repository(self):
    """Tests that the correct result is returned when repository contains the
    owner and repo name (as it does on GitHub)."""
    os.environ['GITHUB_REPOSITORY'] = 'repo/owner'
    self.assertEqual('https://github.com/repo/owner.git',
                     self.github_env.repo_url)

  def test_nongithub_repository(self):
    """Tests that the correct result is returned when repository contains the
    just the repo name (as it does outside of GitHub)."""
    os.environ['REPOSITORY_URL'] = 'https://repo/url'
    self.assertEqual('https://repo/url', self.generic_ci_env.repo_url)


class GetSanitizerTest(unittest.TestCase):
  """Tests for _get_sanitizer."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.sanitizer = 'memory'

  def test_default_value(self):
    """Tests that the default value returned by _get_sanitizer is correct."""
    self.assertEqual(config_utils._get_sanitizer(), 'address')

  def test_normal_case(self):
    """Tests that _get_sanitizer returns the correct value in normal cases."""
    os.environ['SANITIZER'] = self.sanitizer
    self.assertEqual(config_utils._get_sanitizer(), self.sanitizer)

  def test_capitalization(self):
    """Tests that that _get_sanitizer handles capitalization properly."""
    os.environ['SANITIZER'] = self.sanitizer.upper()
    self.assertEqual(config_utils._get_sanitizer(), self.sanitizer)


class ProjectSrcPathTest(unittest.TestCase):
  """Tests for project_src_path."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.workspace = '/workspace'
    os.environ['GITHUB_WORKSPACE'] = self.workspace

    self.project_src_dir_name = 'project-src'

  def test_unset(self):
    """Tests that project_src_path returns None when no PROJECT_SRC_PATH is
    set."""
    github_env = config_utils.GithubEnvironment()
    self.assertIsNone(github_env.project_src_path)

  def test_github(self):
    """Tests that project_src_path returns the correct result on GitHub."""
    os.environ['PROJECT_SRC_PATH'] = self.project_src_dir_name
    expected_project_src_path = os.path.join(self.workspace,
                                             self.project_src_dir_name)
    github_env = config_utils.GithubEnvironment()
    self.assertEqual(github_env.project_src_path, expected_project_src_path)

  def test_not_github(self):
    """Tests that project_src_path returns the correct result not on
    GitHub."""
    project_src_path = os.path.join('/', self.project_src_dir_name)
    os.environ['PROJECT_SRC_PATH'] = project_src_path
    generic_ci_env = config_utils.GenericCiEnvironment()
    self.assertEqual(generic_ci_env.project_src_path, project_src_path)


if __name__ == '__main__':
  unittest.main()
