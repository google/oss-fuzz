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
import sys
import unittest

from pyfakefs import fake_filesystem_unittest

import config_utils

# pylint: disable=wrong-import-position,import-error
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INFRA_DIR)

import test_helpers

# pylint: disable=no-self-use


class BaseConfigTest(fake_filesystem_unittest.TestCase):
  """Tests for BaseConfig."""
  PROJECT_NAME = 'fake-project'

  def setUp(self):
    test_helpers.patch_environ(self)
    os.environ['OSS_FUZZ_PROJECT_NAME'] = self.PROJECT_NAME

  def _create_config(self):
    return config_utils.BuildFuzzersConfig()

  def test_language_internal_default(self):
    """Tests that the correct default language is set for internal projects."""
    os.environ['LANGUAGE'] = 'python'  # Make sure we don't use this.
    config = self._create_config()
    self.assertEqual(config.language, 'c++')

  def test_language_external_default(self):
    """Tests that the correct default language is set for internal projects."""
    os.environ['BUILD_INTEGRATION_PATH'] = '/path'
    config = self._create_config()
    self.assertEqual(config.language, 'c++')

  def test_language_internal(self):
    """Tests that the correct language is set for internal projects."""
    self.setUpPyfakefs()
    project_yaml = os.path.join(os.path.dirname(INFRA_DIR), 'projects',
                                self.PROJECT_NAME, 'project.yaml')
    self.fs.create_file(project_yaml, contents='language: go')
    config = self._create_config()
    self.assertEqual(config.language, 'go')

  def test_language_external(self):
    """Tests that the correct language is set for external projects."""
    os.environ['BUILD_INTEGRATION_PATH'] = '/path'
    language = 'python'
    os.environ['LANGUAGE'] = language
    config = self._create_config()
    self.assertEqual(config.language, language)


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

  def test_keep_unaffected_defaults_to_false(self):
    """Tests that keep_unaffected_fuzz_targets defaults to false."""
    config = self._create_config()
    self.assertFalse(config.keep_unaffected_fuzz_targets)


if __name__ == '__main__':
  unittest.main()
