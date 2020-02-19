# Copyright 2020 Google LLC
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
"""Test the functionality of the fuzz_target module."""

import os
import sys
import tempfile
import unittest
import unittest.mock

# Pylint has issue importing utils which is why error suppression is required.
# pylint: disable=wrong-import-position
# pylint: disable=import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fuzz_target
import utils

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project
EXAMPLE_PROJECT = 'example'


class IsReproducibleUnitTest(unittest.TestCase):
  """Test is_reproducible function in the fuzz_target module."""

  def setUp(self):
    """Sets up dummy fuzz target to test is_reproducible method."""
    self.test_target = fuzz_target.FuzzTarget('/example/path', 10,
                                              '/example/outdir')

  def test_with_reproducible(self):
    """Tests that a is_reproducible will return true if crash is detected."""
    test_all_success = [(0, 0, 1)] * 10
    all_success_mock = unittest.mock.Mock()
    all_success_mock.side_effect = test_all_success
    utils.execute = all_success_mock
    self.assertTrue(
        self.test_target.is_reproducible('/fake/path/to/testcase',
                                         '/fake/target'))
    self.assertEqual(1, all_success_mock.call_count)

    test_one_success = [(0, 0, 0)] * 9 + [(0, 0, 1)]
    one_success_mock = unittest.mock.Mock()
    one_success_mock.side_effect = test_one_success
    utils.execute = one_success_mock
    self.assertTrue(
        self.test_target.is_reproducible('/fake/path/to/testcase',
                                         '/fake/target'))
    self.assertEqual(10, one_success_mock.call_count)

  def test_with_not_reproducible(self):
    """Tests that a is_reproducible will return False if crash not detected."""
    test_all_fail = [(0, 0, 0)] * 10
    all_fail_mock = unittest.mock.Mock()
    all_fail_mock.side_effect = test_all_fail
    utils.execute = all_fail_mock
    self.assertFalse(
        self.test_target.is_reproducible('/fake/path/to/testcase',
                                         '/fake/target'))


class GetTestCaseUnitTest(unittest.TestCase):
  """Test get_test_case function in the fuzz_target module."""

  def setUp(self):
    """Sets up dummy fuzz target to test get_test_case method."""
    self.test_target = fuzz_target.FuzzTarget('/example/path', 10,
                                              '/example/outdir')

  def test_with_valid_error_string(self):
    """Tests that get_test_case returns the correct test case give an error."""
    test_case_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'test_files', 'example_fuzzer_output.txt')
    with open(test_case_path, 'r') as test_fuzz_output:
      parsed_test_case = self.test_target.get_test_case(test_fuzz_output.read())
    self.assertEqual(
        parsed_test_case,
        '/example/outdir/crash-ad6700613693ef977ff3a8c8f4dae239c3dde6f5')

  def test_with_invalid_error_string(self):
    """Tests that get_test_case will return None with a bad error string."""
    self.assertIsNone(self.test_target.get_test_case(''))
    self.assertIsNone(self.test_target.get_test_case(' Example crash string.'))


class CheckReproducibilityAndRegressionUnitTest(unittest.TestCase):
  """Test check_reproducibility_and_regression function fuzz_target module."""

  def setUp(self):
    """Sets up dummy fuzz target to test is_reproducible method."""
    self.test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                              '/example/outdir', 'example')

  def test_with_valid_crash(self):
    """Checks to make sure a valid crash returns true."""
    with unittest.mock.patch.object(
        fuzz_target.FuzzTarget, 'is_reproducible',
        side_effect=[True, False]), tempfile.TemporaryDirectory() as tmp_dir:
      self.test_target.out_dir = tmp_dir
      self.assertTrue(
          self.test_target.check_reproducibility_and_regression(
              '/example/crash/testcase'))

  def test_with_invalid_crash(self):
    """Checks to make sure an invalid crash returns false."""
    with unittest.mock.patch.object(fuzz_target.FuzzTarget,
                                    'is_reproducible',
                                    side_effect=[True, True]):
      self.assertFalse(
          self.test_target.check_reproducibility_and_regression(
              '/example/crash/testcase'))

    with unittest.mock.patch.object(fuzz_target.FuzzTarget,
                                    'is_reproducible',
                                    side_effect=[False, True]):
      self.assertFalse(
          self.test_target.check_reproducibility_and_regression(
              '/example/crash/testcase'))

    with unittest.mock.patch.object(fuzz_target.FuzzTarget,
                                    'is_reproducible',
                                    side_effect=[False, False]):
      self.assertFalse(
          self.test_target.check_reproducibility_and_regression(
              '/example/crash/testcase'))


class GetLatestBuildVersionUnitTest(unittest.TestCase):
  """Test the get_latest_build_version function in the fuzz_target module."""

  def test_get_valid_project(self):
    """Checks the latest build can be retrieved from gcs."""
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir',
                                         'example')
    latest_build = test_target.get_lastest_build_version()
    self.assertIsNotNone(latest_build)
    self.assertTrue(latest_build.endswith('.zip'))
    self.assertTrue('address' in latest_build)

  def test_get_invalid_project(self):
    """Checks the latest build will return None when project doesn't exist."""
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir',
                                         'not-a-proj')
    self.assertIsNone(test_target.get_lastest_build_version())
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir')
    self.assertIsNone(test_target.get_lastest_build_version())


class DownloadOSSFuzzBuildDirIntegrationTests(unittest.TestCase):
  """Test the download_oss_fuzz_build in function in the fuzz_target module."""

  def test_single_download(self):
    """Checks that the build directory was only downloaded once."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'example')
      latest_version = test_target.get_lastest_build_version()
      with unittest.mock.patch.object(
          fuzz_target.FuzzTarget,
          'get_lastest_build_version',
          return_value=latest_version) as mock_build_version:
        for _ in range(5):
          oss_fuzz_build_path = test_target.download_oss_fuzz_build()
        self.assertEqual(1, mock_build_version.call_count)
        self.assertIsNotNone(oss_fuzz_build_path)
        self.assertTrue(os.listdir(oss_fuzz_build_path))

  def test_get_valid_project(self):
    """Checks the latest build can be retrieved from gcs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'example')
      oss_fuzz_build_path = test_target.download_oss_fuzz_build()
      self.assertIsNotNone(oss_fuzz_build_path)
      self.assertTrue(os.listdir(oss_fuzz_build_path))

  def test_get_invalid_project(self):
    """Checks the latest build will return None when project doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir)
      self.assertIsNone(test_target.download_oss_fuzz_build())
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'not-a-proj')
      self.assertIsNone(test_target.download_oss_fuzz_build())

  def test_invalid_build_dir(self):
    """Checks the download will return None when out_dir doesn't exist."""
    test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                         'not/a/dir', 'example')
    self.assertIsNone(test_target.download_oss_fuzz_build())


if __name__ == '__main__':
  unittest.main()
