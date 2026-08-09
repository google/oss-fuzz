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
import shutil
import tempfile
import unittest
from unittest import mock

import certifi
# Importing this later causes import failures with pytest for some reason.
# TODO(ochang): Figure out why.
import parameterized
import google.cloud.ndb  # pylint: disable=unused-import
from pyfakefs import fake_filesystem_unittest
from clusterfuzz.fuzz import engine

import clusterfuzz_deployment
import fuzz_target
import test_helpers
import workspace_utils

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# An example fuzzer that triggers an error.
EXAMPLE_FUZZER = 'example_crash_fuzzer'

# Mock return values for engine_impl.reproduce.
EXECUTE_SUCCESS_RESULT = engine.ReproduceResult([], 0, 0, '')
EXECUTE_FAILURE_RESULT = engine.ReproduceResult([], 1, 0, '')

TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), 'test_data')


def _create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  defaults = {
      'cfl_platform': 'github',
      'oss_fuzz_project_name': EXAMPLE_PROJECT,
      'workspace': '/workspace'
  }
  for default_key, default_value in defaults.items():
    if default_key not in kwargs:
      kwargs[default_key] = default_value

  return test_helpers.create_run_config(**kwargs)


def _create_deployment(**kwargs):
  config = _create_config(**kwargs)
  workspace = workspace_utils.Workspace(config)
  return clusterfuzz_deployment.get_clusterfuzz_deployment(config, workspace)


@mock.patch('utils.get_container_name', return_value='container')
class IsReproducibleTest(fake_filesystem_unittest.TestCase):
  """Tests the is_reproducible method in the fuzz_target.FuzzTarget class."""

  def setUp(self):
    """Sets up example fuzz target to test is_reproducible method."""
    self.fuzz_target_name = 'fuzz-target'
    deployment = _create_deployment()
    self.config = deployment.config
    self.workspace = deployment.workspace
    self.fuzz_target_path = os.path.join(self.workspace.out,
                                         self.fuzz_target_name)
    self.setUpPyfakefs()
    self.fs.create_file(self.fuzz_target_path)
    self.testcase_path = '/testcase'
    self.fs.create_file(self.testcase_path)

    self.target = fuzz_target.FuzzTarget(self.fuzz_target_path,
                                         fuzz_target.REPRODUCE_ATTEMPTS,
                                         self.workspace, deployment,
                                         deployment.config)

    # ClusterFuzz requires ROOT_DIR.
    root_dir = os.environ['ROOT_DIR']
    test_helpers.patch_environ(self, empty=True)
    os.environ['ROOT_DIR'] = root_dir

  # There's an extremely bad issue that happens if this test is run: Other tests
  # in this file fail in CI with stacktraces using referencing fakefs even if
  # the tests do not use fakefs.
  # TODO(metzman): Stop using fakefs.
  @mock.patch('os.chmod')
  @unittest.skip('Skip because of weird failures.')
  def test_repro_timed_out(self, mock_chmod, mock_get_container_name):
    """Tests that is_reproducible behaves correctly when reproduction times
    out."""
    del mock_get_container_name
    del mock_chmod

    with mock.patch(
        'clusterfuzz._internal.bot.fuzzers.libFuzzer.engine.LibFuzzerEngine.'
        'reproduce',
        side_effect=TimeoutError):
      self.assertFalse(
          self.target.is_reproducible('/testcase', self.target.target_path, []))

  def test_reproducible(self, _):
    """Tests that is_reproducible returns True if crash is detected and that
    is_reproducible uses the correct command to reproduce a crash."""
    all_repro = [EXECUTE_FAILURE_RESULT] * fuzz_target.REPRODUCE_ATTEMPTS
    with mock.patch('clusterfuzz.fuzz.get_engine') as mock_get_engine:
      mock_get_engine().reproduce.side_effect = all_repro

      result = self.target.is_reproducible(self.testcase_path,
                                           self.fuzz_target_path, [])
      mock_get_engine().reproduce.assert_called_once_with(
          '/workspace/build-out/fuzz-target',
          '/testcase',
          arguments=[],
          max_time=30)
      self.assertTrue(result)
      self.assertEqual(1, mock_get_engine().reproduce.call_count)

  def test_flaky(self, _):
    """Tests that is_reproducible returns True if crash is detected on the last
    attempt."""
    last_time_repro = [EXECUTE_SUCCESS_RESULT] * 9 + [EXECUTE_FAILURE_RESULT]
    with mock.patch('clusterfuzz.fuzz.get_engine') as mock_get_engine:
      mock_get_engine().reproduce.side_effect = last_time_repro
      self.assertTrue(
          self.target.is_reproducible(self.testcase_path, self.fuzz_target_path,
                                      []))
      self.assertEqual(fuzz_target.REPRODUCE_ATTEMPTS,
                       mock_get_engine().reproduce.call_count)

  def test_nonexistent_fuzzer(self, _):
    """Tests that is_reproducible raises an error if it could not attempt
    reproduction because the fuzzer doesn't exist."""
    with self.assertRaises(fuzz_target.ReproduceError):
      self.target.is_reproducible(self.testcase_path, '/non-existent-path', [])

  def test_unreproducible(self, _):
    """Tests that is_reproducible returns False for a crash that did not
    reproduce."""
    all_unrepro = [EXECUTE_SUCCESS_RESULT] * fuzz_target.REPRODUCE_ATTEMPTS
    with mock.patch('clusterfuzz.fuzz.get_engine') as mock_get_engine:
      mock_get_engine().reproduce.side_effect = all_unrepro
      result = self.target.is_reproducible(self.testcase_path,
                                           self.fuzz_target_path, [])
      self.assertFalse(result)


class IsCrashReportableTest(fake_filesystem_unittest.TestCase):
  """Tests the is_crash_reportable method of FuzzTarget."""

  def setUp(self):
    """Sets up example fuzz target to test is_crash_reportable method."""
    self.setUpPyfakefs()
    self.fuzz_target_path = '/example/do_stuff_fuzzer'
    deployment = _create_deployment()
    self.target = fuzz_target.FuzzTarget(self.fuzz_target_path, 100,
                                         deployment.workspace, deployment,
                                         deployment.config)
    self.oss_fuzz_build_path = '/oss-fuzz-build'
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
  def test_new_reproducible_crash(self, mock_info, _):
    """Tests that a new reproducible crash returns True."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.target.out_dir = tmp_dir
      self.assertTrue(self.target.is_crash_reportable(self.testcase_path, []))
    mock_info.assert_called_with(
        'The crash is not reproducible on previous build. '
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
        self.assertFalse(self.target.is_crash_reportable(
            self.testcase_path, []))

  @mock.patch('logging.info')
  @mock.patch('fuzz_target.FuzzTarget.is_reproducible', return_value=[True])
  def test_reproducible_no_oss_fuzz_target(self, _, mock_info):
    """Tests that is_crash_reportable returns True when a crash reproduces on
    the PR build but the target is not in the OSS-Fuzz build (usually because it
    is new)."""
    os.remove(self.oss_fuzz_target_path)

    def is_reproducible_side_effect(testcase, target_path, reproduce_arguments):
      del testcase
      del reproduce_arguments
      if os.path.dirname(target_path) == self.oss_fuzz_build_path:
        raise fuzz_target.ReproduceError()
      return True

    with mock.patch(
        'fuzz_target.FuzzTarget.is_reproducible',
        side_effect=is_reproducible_side_effect) as mock_is_reproducible:
      with mock.patch('clusterfuzz_deployment.OSSFuzz.download_latest_build',
                      return_value=self.oss_fuzz_build_path):
        self.assertTrue(self.target.is_crash_reportable(self.testcase_path, []))
    mock_is_reproducible.assert_any_call(self.testcase_path,
                                         self.oss_fuzz_target_path, [])
    mock_info.assert_called_with(
        'Could not run previous build of target to determine if this code '
        'change (pr/commit) introduced crash. Assuming crash was newly '
        'introduced.')


class FuzzTest(fake_filesystem_unittest.TestCase):
  """Fuzz test."""

  def setUp(self):
    """Sets up example fuzz target."""
    self.setUpPyfakefs()
    deployment = _create_deployment()
    config = deployment.config
    workspace = deployment.workspace
    self.fuzz_target = fuzz_target.FuzzTarget('/path/fuzz-target', 10,
                                              workspace, deployment, config)

  def test_get_fuzz_target_artifact(self):
    """Tests that get_fuzz_target_artifact works as intended."""
    # pylint: disable=protected-access
    fuzz_target_artifact = self.fuzz_target._target_artifact_path()
    self.assertEqual('/workspace/out/artifacts/fuzz-target/address',
                     fuzz_target_artifact)


class TimeoutIntegrationTest(unittest.TestCase):
  """Tests handling of fuzzer timeout (timeout crashes reported by
  libFuzzer)."""
  TIMEOUT_FUZZER_NAME = 'timeout_fuzzer'

  @parameterized.parameterized.expand([(True, True), (False, False)])
  def test_timeout_reported(self, report_timeouts, expect_crash):
    """Tests that timeouts are not reported."""
    with test_helpers.temp_dir_copy(TEST_DATA_PATH) as temp_dir:
      fuzz_target_path = os.path.join(temp_dir, 'build-out',
                                      self.TIMEOUT_FUZZER_NAME)
      shutil.copy(os.path.join(temp_dir, self.TIMEOUT_FUZZER_NAME),
                  fuzz_target_path)
      deployment = _create_deployment(workspace=temp_dir,
                                      report_timeouts=report_timeouts)
      config = deployment.config
      fuzz_target_obj = fuzz_target.FuzzTarget(fuzz_target_path,
                                               fuzz_target.REPRODUCE_ATTEMPTS,
                                               deployment.workspace, deployment,
                                               config)
      with mock.patch('clusterfuzz._internal.bot.fuzzers.libfuzzer.'
                      'fix_timeout_argument_for_reproduction') as _:
        with mock.patch(
            'clusterfuzz._internal.bot.fuzzers.libFuzzer.fuzzer.get_arguments',
            return_value=['-timeout=1', '-rss_limit_mb=2560']):
          fuzz_result = fuzz_target_obj.fuzz()
    self.assertEqual(bool(fuzz_result.testcase), expect_crash)


if __name__ == '__main__':
  unittest.main()
