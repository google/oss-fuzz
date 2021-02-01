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
"""Tests for running fuzzers."""
import os
import sys
import tempfile
import unittest
from unittest import mock

import config_utils
import fuzz_target
import run_fuzzers

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INFRA_DIR)

import test_helpers

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# Location of files used for testing.
TEST_FILES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'test_files')

MEMORY_FUZZER_DIR = os.path.join(TEST_FILES_PATH, 'memory')
MEMORY_FUZZER = 'curl_fuzzer_memory'

UNDEFINED_FUZZER_DIR = os.path.join(TEST_FILES_PATH, 'undefined')
UNDEFINED_FUZZER = 'curl_fuzzer_undefined'


def create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  with mock.patch('os.path.basename', return_value=None), mock.patch(
      'config_utils.get_project_src_path',
      return_value=None), mock.patch('config_utils._is_dry_run',
                                     return_value=True):
    config = config_utils.RunFuzzersConfig()

  for key, value in kwargs.items():
    assert hasattr(config, key), 'Config doesn\'t have attribute: ' + key
    setattr(config, key, value)
  return config


class RunFuzzerIntegrationTestMixin:  # pylint: disable=too-few-public-methods,invalid-name
  """Mixin for integration test classes that runbuild_fuzzers on builds of a
  specific sanitizer."""
  # These must be defined by children.
  FUZZER_DIR = None
  FUZZER = None

  def _test_run_with_sanitizer(self, fuzzer_dir, sanitizer):
    """Calls run_fuzzers on fuzzer_dir and |sanitizer| and asserts
    the run succeeded and that no bug was found."""
    with test_helpers.temp_dir_copy(fuzzer_dir) as fuzzer_dir_copy:
      config = create_config(fuzz_seconds=10,
                             workspace=fuzzer_dir_copy,
                             project_name='curl',
                             sanitizer=sanitizer)
      run_success, bug_found = run_fuzzers.run_fuzzers(config)
    self.assertTrue(run_success)
    self.assertFalse(bug_found)


class RunMemoryFuzzerIntegrationTest(RunFuzzerIntegrationTestMixin,
                                     unittest.TestCase):
  """Integration test for build_fuzzers with an MSAN build."""
  FUZZER_DIR = MEMORY_FUZZER_DIR
  FUZZER = MEMORY_FUZZER

  @unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                   'INTEGRATION_TESTS=1 not set')
  def test_run_with_memory_sanitizer(self):
    """Tests run_fuzzers with a valid MSAN build."""
    self._test_run_with_sanitizer(self.FUZZER_DIR, 'memory')


class RunUndefinedFuzzerIntegrationTest(RunFuzzerIntegrationTestMixin,
                                        unittest.TestCase):
  """Integration test for build_fuzzers with an UBSAN build."""
  FUZZER_DIR = UNDEFINED_FUZZER_DIR
  FUZZER = UNDEFINED_FUZZER

  @unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                   'INTEGRATION_TESTS=1 not set')
  def test_run_with_undefined_sanitizer(self):
    """Tests run_fuzzers with a valid UBSAN build."""
    self._test_run_with_sanitizer(self.FUZZER_DIR, 'undefined')


class RunAddressFuzzersIntegrationTest(RunFuzzerIntegrationTestMixin,
                                       unittest.TestCase):
  """Integration tests for build_fuzzers with an ASAN build."""

  @unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                   'INTEGRATION_TESTS=1 not set')
  def test_new_bug_found(self):
    """Tests run_fuzzers with a valid ASAN build."""
    # Set the first return value to True, then the second to False to
    # emulate a bug existing in the current PR but not on the downloaded
    # OSS-Fuzz build.
    with mock.patch.object(fuzz_target.FuzzTarget,
                           'is_reproducible',
                           side_effect=[True, False]):
      config = create_config(fuzz_seconds=10,
                             workspace=TEST_FILES_PATH,
                             project_name=EXAMPLE_PROJECT)
      run_success, bug_found = run_fuzzers.run_fuzzers(config)
      build_dir = os.path.join(TEST_FILES_PATH, 'out', 'oss_fuzz_latest')
      self.assertTrue(os.path.exists(build_dir))
      self.assertNotEqual(0, len(os.listdir(build_dir)))
      self.assertTrue(run_success)
      self.assertTrue(bug_found)

  @unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                   'INTEGRATION_TESTS=1 not set')
  def test_old_bug_found(self):
    """Tests run_fuzzers with a bug found in OSS-Fuzz before."""
    config = create_config(fuzz_seconds=10,
                           workspace=TEST_FILES_PATH,
                           project_name=EXAMPLE_PROJECT)
    with mock.patch.object(fuzz_target.FuzzTarget,
                           'is_reproducible',
                           side_effect=[True, True]):
      config = create_config(fuzz_seconds=10,
                             workspace=TEST_FILES_PATH,
                             project_name=EXAMPLE_PROJECT)
      run_success, bug_found = run_fuzzers.run_fuzzers(config)
      build_dir = os.path.join(TEST_FILES_PATH, 'out', 'oss_fuzz_latest')
      self.assertTrue(os.path.exists(build_dir))
      self.assertNotEqual(0, len(os.listdir(build_dir)))
      self.assertTrue(run_success)
      self.assertFalse(bug_found)

  def test_invalid_build(self):
    """Tests run_fuzzers with an invalid ASAN build."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'out')
      os.mkdir(out_path)
      config = create_config(fuzz_seconds=10,
                             workspace=tmp_dir,
                             project_name=EXAMPLE_PROJECT)
      run_success, bug_found = run_fuzzers.run_fuzzers(config)
    self.assertFalse(run_success)
    self.assertFalse(bug_found)

  def test_invalid_fuzz_seconds(self):
    """Tests run_fuzzers with an invalid fuzz seconds."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'out')
      os.mkdir(out_path)
      config = create_config(fuzz_seconds=0,
                             workspace=tmp_dir,
                             project_name=EXAMPLE_PROJECT)
      run_success, bug_found = run_fuzzers.run_fuzzers(config)
    self.assertFalse(run_success)
    self.assertFalse(bug_found)

  def test_invalid_out_dir(self):
    """Tests run_fuzzers with an invalid out directory."""
    config = create_config(fuzz_seconds=10,
                           workspace='not/a/valid/path',
                           project_name=EXAMPLE_PROJECT)
    run_success, bug_found = run_fuzzers.run_fuzzers(config)
    self.assertFalse(run_success)
    self.assertFalse(bug_found)


if __name__ == '__main__':
  unittest.main()
