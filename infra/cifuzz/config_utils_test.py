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

import config_utils
import test_helpers

# pylint: disable=no-self-use


class BaseConfigTest(unittest.TestCase):
  """Tests for BaseConfig."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def _create_config(self):
    return config_utils.BuildFuzzersConfig()

  def test_language_default(self):
    """Tests that the correct default language is set."""
    os.environ['BUILD_INTEGRATION_PATH'] = '/path'
    config = self._create_config()
    self.assertEqual(config.language, 'c++')

  def test_language(self):
    """Tests that the correct language is set."""
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
