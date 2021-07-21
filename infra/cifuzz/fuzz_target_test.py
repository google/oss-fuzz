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
"""Tests the functionality of the fuzz_target module."""

import os
import tempfile
import unittest
from unittest import mock

import certifi
import parameterized
from pyfakefs import fake_filesystem_unittest

import clusterfuzz_deployment
import docker
import fuzz_target
import test_helpers

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# An example fuzzer that triggers an error.
EXAMPLE_FUZZER = 'example_crash_fuzzer'

# The return value of a successful call to utils.execute.
EXECUTE_SUCCESS_RETVAL = ('', '', 0)

# The return value of a failed call to utils.execute.
EXECUTE_FAILURE_RETVAL = ('', '', 1)


def _create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  defaults = {
      'is_github': True,
      'oss_fuzz_project_name': EXAMPLE_PROJECT,
      'workspace': '/workspace'
  }
  for default_key, default_value in defaults.items():
    if default_key not in kwargs:
      kwargs[default_key] = default_value

  return test_helpers.create_run_config(**kwargs)


def _create_deployment(**kwargs):
  config = _create_config(**kwargs)
  workspace = docker.Workspace(config)
  return clusterfuzz_deployment.get_clusterfuzz_deployment(config, workspace)


# TODO(metzman): Use patch from test_libs/helpers.py in clusterfuzz so that we
# don't need to accept this as an argument in every test method.
@mock.patch('utils.get_container_name', return_value='container')
class IsReproducibleTest(fake_filesystem_unittest.TestCase):
  """Tests the is_reproducible method in the fuzz_target.FuzzTarget class."""

  def setUp(self):
    """Sets up example fuzz target to test is_reproducible method."""
    self.fuzz_target_name = 'fuzz-target'
    deployment = _create_deployment()
    self.workspace = deployment.workspace
    self.fuzz_target_path = os.path.join(self.workspace.out,
                                         self.fuzz_target_name)
    self.testcase_path = '/testcase'
    self.test_target = fuzz_target.FuzzTarget(self.fuzz_target_path,
                                              fuzz_target.REPRODUCE_ATTEMPTS,
                                              self.workspace, deployment,
                                              deployment.config)

  def test_reproducible(self, _):
    """Tests that is_reproducible returns True if crash is detected and that
    is_reproducible uses the correct command to reproduce a crash."""
    self._set_up_fakefs()
    all_repro = [EXECUTE_FAILURE_RETVAL] * fuzz_target.REPRODUCE_ATTEMPTS
    with mock.patch('utils.execute', side_effect=all_repro) as mocked_execute:
      result = self.test_target.is_reproducible(self.testcase_path,
                                                self.fuzz_target_path)
      mocked_execute.assert_called_once_with([
          'docker', 'run', '--rm', '--privileged', '--cap-add', 'SYS_PTRACE',
          '-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'ARCHITECTURE=x86_64', '-e',
          'CIFUZZ=True', '-e', 'SANITIZER=' + self.test_target.config.sanitizer,
          '-e', 'FUZZING_LANGUAGE=' + self.test_target.config.language, '-e',
          'OUT=' + self.workspace.out, '--volumes-from', 'container', '-e',
          'TESTCASE=' + self.testcase_path, '-t',
          'gcr.io/oss-fuzz-base/base-runner', 'reproduce',
          self.fuzz_target_name, '-runs=100'
      ])
      self.assertTrue(result)
      self.assertEqual(1, mocked_execute.call_count)

  def _set_up_fakefs(self):
    """Helper to setup pyfakefs and add important files to the fake
    filesystem."""
    self.setUpPyfakefs()
    self.fs.create_file(self.fuzz_target_path)
    self.fs.create_file(self.testcase_path)

  def test_flaky(self, _):
    """Tests that is_reproducible returns True if crash is detected on the last
    attempt."""
    self._set_up_fakefs()
    last_time_repro = [EXECUTE_SUCCESS_RETVAL] * 9 + [EXECUTE_FAILURE_RETVAL]
    with mock.patch('utils.execute',
                    side_effect=last_time_repro) as mocked_execute:
      self.assertTrue(
          self.test_target.is_reproducible(self.testcase_path,
                                           self.fuzz_target_path))
      self.assertEqual(fuzz_target.REPRODUCE_ATTEMPTS,
                       mocked_execute.call_count)

  def test_nonexistent_fuzzer(self, _):
    """Tests that is_reproducible raises an error if it could not attempt
    reproduction because the fuzzer doesn't exist."""
    with self.assertRaises(fuzz_target.ReproduceError):
      self.test_target.is_reproducible(self.testcase_path, '/non-existent-path')

  def test_unreproducible(self, _):
    """Tests that is_reproducible returns False for a crash that did not
    reproduce."""
    all_unrepro = [EXECUTE_SUCCESS_RETVAL] * fuzz_target.REPRODUCE_ATTEMPTS
    self._set_up_fakefs()
    with mock.patch('utils.execute', side_effect=all_unrepro):
      result = self.test_target.is_reproducible(self.testcase_path,
                                                self.fuzz_target_path)
      self.assertFalse(result)


class GetTestCaseTest(unittest.TestCase):
  """Tests get_testcase."""

  def test_valid_error_string(self):
    """Tests that get_testcase returns the correct testcase give an error."""
    testcase_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'test_data', 'example_crash_fuzzer_output.txt')
    with open(testcase_path, 'rb') as test_fuzz_output:
      parsed_testcase = fuzz_target.get_testcase(test_fuzz_output.read())
    self.assertEqual(parsed_testcase,
                     './crash-ad6700613693ef977ff3a8c8f4dae239c3dde6f5')

  def test_invalid_error_string(self):
    """Tests that get_testcase returns None with a bad error string."""
    self.assertIsNone(fuzz_target.get_testcase(b''))
    self.assertIsNone(fuzz_target.get_testcase(b' Example crash string.'))

  def test_encoding(self):
    """Tests that get_testcase accepts bytes and returns a string."""
    fuzzer_output = b'\x8fTest unit written to ./crash-1'
    result = fuzz_target.get_testcase(fuzzer_output)
    self.assertTrue(isinstance(result, str))


class IsCrashReportableTest(fake_filesystem_unittest.TestCase):
  """Tests the is_crash_reportable method of FuzzTarget."""

  def setUp(self):
    """Sets up example fuzz target to test is_crash_reportable method."""
    self.fuzz_target_path = '/example/do_stuff_fuzzer'
    deployment = _create_deployment()
    self.test_target = fuzz_target.FuzzTarget(self.fuzz_target_path, 100,
                                              '/example/outdir', deployment,
                                              deployment.config)
    self.oss_fuzz_build_path = '/oss-fuzz-build'
    self.setUpPyfakefs()
    self.fs.create_file(self.fuzz_target_path)
    self.oss_fuzz_target_path = os.path.join(
        self.oss_fuzz_build_path, os.path.basename(self.fuzz_target_path))
    self.fs.create_file(self.oss_fuzz_target_path)
    self.testcase_path = '/testcase'
    self.fs.create_file(self.testcase_path, contents='')

    # Do this to prevent pyfakefs from messing with requests.
    self.fs.add_real_directory(os.path.dirname(certifi.__file__))

  @mock.patch('fuzz_target.FuzzTarget.is_reproducible',
              side_effect=[True, False])
  @mock.patch('logging.info')
  def test_new_reproducible_crash(self, mocked_info, _):
    """Tests that a new reproducible crash returns True."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.test_target.out_dir = tmp_dir
      self.assertTrue(self.test_target.is_crash_reportable(self.testcase_path))
    mocked_info.assert_called_with(
        'The crash doesn\'t reproduce on previous build. '
        'Code change (pr/commit) introduced crash.')

  # yapf: disable
  @parameterized.parameterized.expand([
      # Reproducible on PR build, but also reproducible on OSS-Fuzz.
      ([True, True],),

      # Not reproducible on PR build, but somehow reproducible on OSS-Fuzz.
      # Unlikely to happen in real world except if test is flaky.
      ([False, True],),

      # Not reproducible on PR build, and not reproducible on OSS-Fuzz.
      ([False, False],),
  ])
  # yapf: enable
  def test_invalid_crash(self, is_reproducible_retvals):
    """Tests that a nonreportable crash causes the method to return False."""
    with mock.patch('fuzz_target.FuzzTarget.is_reproducible',
                    side_effect=is_reproducible_retvals):
      with mock.patch('clusterfuzz_deployment.OSSFuzz.download_latest_build',
                      return_value=self.oss_fuzz_build_path):
        self.assertFalse(
            self.test_target.is_crash_reportable(self.testcase_path))

  @mock.patch('logging.info')
  @mock.patch('fuzz_target.FuzzTarget.is_reproducible', return_value=[True])
  def test_reproducible_no_oss_fuzz_target(self, _, mocked_info):
    """Tests that is_crash_reportable returns True when a crash reproduces on
    the PR build but the target is not in the OSS-Fuzz build (usually because it
    is new)."""
    os.remove(self.oss_fuzz_target_path)

    def is_reproducible_side_effect(_, target_path):
      if os.path.dirname(target_path) == self.oss_fuzz_build_path:
        raise fuzz_target.ReproduceError()
      return True

    with mock.patch(
        'fuzz_target.FuzzTarget.is_reproducible',
        side_effect=is_reproducible_side_effect) as mocked_is_reproducible:
      with mock.patch('clusterfuzz_deployment.OSSFuzz.download_latest_build',
                      return_value=self.oss_fuzz_build_path):
        self.assertTrue(self.test_target.is_crash_reportable(
            self.testcase_path))
    mocked_is_reproducible.assert_any_call(self.testcase_path,
                                           self.oss_fuzz_target_path)
    mocked_info.assert_called_with(
        'Could not run previous build of target to determine if this code '
        'change (pr/commit) introduced crash. Assuming crash was newly '
        'introduced.')


if __name__ == '__main__':
  unittest.main()
