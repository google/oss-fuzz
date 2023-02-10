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
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

import parameterized
from pyfakefs import fake_filesystem_unittest

import build_fuzzers
import fuzz_target
import run_fuzzers

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INFRA_DIR)

import helper
import test_helpers

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# Location of files used for testing.
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'test_data')

MEMORY_FUZZER_DIR = os.path.join(TEST_DATA_PATH, 'memory')
MEMORY_FUZZER = 'curl_fuzzer_memory'

UNDEFINED_FUZZER_DIR = os.path.join(TEST_DATA_PATH, 'undefined')
UNDEFINED_FUZZER = 'curl_fuzzer_undefined'

FUZZ_SECONDS = 10


class RunFuzzerIntegrationTestMixin:  # pylint: disable=too-few-public-methods,invalid-name
  """Mixin for integration test classes that runbuild_fuzzers on builds of a
  specific sanitizer."""
  # These must be defined by children.
  FUZZER_DIR = None
  FUZZER = None

  def setUp(self):
    """Patch the environ so that we can execute runner scripts."""
    test_helpers.patch_environ(self, runner=True)

  def _test_run_with_sanitizer(self, fuzzer_dir, sanitizer):
    """Calls run_fuzzers on fuzzer_dir and |sanitizer| and asserts
    the run succeeded and that no bug was found."""
    with test_helpers.temp_dir_copy(fuzzer_dir) as fuzzer_dir_copy:
      config = test_helpers.create_run_config(fuzz_seconds=FUZZ_SECONDS,
                                              workspace=fuzzer_dir_copy,
                                              oss_fuzz_project_name='curl',
                                              sanitizer=sanitizer)
      result = run_fuzzers.run_fuzzers(config)
    self.assertEqual(result, run_fuzzers.RunFuzzersResult.NO_BUG_FOUND)


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class RunMemoryFuzzerIntegrationTest(RunFuzzerIntegrationTestMixin,
                                     unittest.TestCase):
  """Integration test for build_fuzzers with an MSAN build."""
  FUZZER_DIR = MEMORY_FUZZER_DIR
  FUZZER = MEMORY_FUZZER

  def test_run_with_memory_sanitizer(self):
    """Tests run_fuzzers with a valid MSAN build."""
    self._test_run_with_sanitizer(self.FUZZER_DIR, 'memory')


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class RunUndefinedFuzzerIntegrationTest(RunFuzzerIntegrationTestMixin,
                                        unittest.TestCase):
  """Integration test for build_fuzzers with an UBSAN build."""
  FUZZER_DIR = UNDEFINED_FUZZER_DIR
  FUZZER = UNDEFINED_FUZZER

  def test_run_with_undefined_sanitizer(self):
    """Tests run_fuzzers with a valid UBSAN build."""
    self._test_run_with_sanitizer(self.FUZZER_DIR, 'undefined')


class BaseFuzzTargetRunnerTest(unittest.TestCase):
  """Tests BaseFuzzTargetRunner."""

  def _create_runner(self, **kwargs):  # pylint: disable=no-self-use
    defaults = {
        'fuzz_seconds': FUZZ_SECONDS,
        'oss_fuzz_project_name': EXAMPLE_PROJECT
    }
    for default_key, default_value in defaults.items():
      if default_key not in kwargs:
        kwargs[default_key] = default_value

    config = test_helpers.create_run_config(**kwargs)
    return run_fuzzers.BaseFuzzTargetRunner(config)

  def _test_initialize_fail(self, expected_error_args, **create_runner_kwargs):
    with mock.patch('logging.error') as mock_error:
      runner = self._create_runner(**create_runner_kwargs)
      self.assertFalse(runner.initialize())
      mock_error.assert_called_with(*expected_error_args)

  @parameterized.parameterized.expand([(0,), (None,), (-1,)])
  def test_initialize_invalid_fuzz_seconds(self, fuzz_seconds):
    """Tests initialize fails with an invalid fuzz seconds."""
    expected_error_args = ('Fuzz_seconds argument must be greater than 1, '
                           'but was: %s.', fuzz_seconds)
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      with mock.patch('utils.get_fuzz_targets') as mock_get_fuzz_targets:
        mock_get_fuzz_targets.return_value = [
            os.path.join(out_path, 'fuzz_target')
        ]
        self._test_initialize_fail(expected_error_args,
                                   fuzz_seconds=fuzz_seconds,
                                   workspace=tmp_dir)

  def test_initialize_no_out_dir(self):
    """Tests initialize fails with no out dir."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      expected_error_args = ('Out directory: %s does not exist.', out_path)
      self._test_initialize_fail(expected_error_args, workspace=tmp_dir)

  def test_initialize_nonempty_artifacts(self):
    """Tests initialize with a file artifacts path."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      os.makedirs(os.path.join(tmp_dir, 'out'))
      artifacts_path = os.path.join(tmp_dir, 'out', 'artifacts')
      with open(artifacts_path, 'w') as artifacts_handle:
        artifacts_handle.write('fake')
      expected_error_args = (
          'Artifacts path: %s exists and is not an empty directory.',
          artifacts_path)
      self._test_initialize_fail(expected_error_args, workspace=tmp_dir)

  def test_initialize_bad_artifacts(self):
    """Tests initialize with a non-empty artifacts path."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      artifacts_path = os.path.join(tmp_dir, 'out', 'artifacts')
      os.makedirs(artifacts_path)
      artifact_path = os.path.join(artifacts_path, 'artifact')
      with open(artifact_path, 'w') as artifact_handle:
        artifact_handle.write('fake')
      expected_error_args = (
          'Artifacts path: %s exists and is not an empty directory.',
          artifacts_path)
      self._test_initialize_fail(expected_error_args, workspace=tmp_dir)

  @mock.patch('utils.get_fuzz_targets')
  @mock.patch('logging.error')
  def test_initialize_empty_artifacts(self, mock_log_error,
                                      mock_get_fuzz_targets):
    """Tests initialize with an empty artifacts dir."""
    mock_get_fuzz_targets.return_value = ['fuzz-target']
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      artifacts_path = os.path.join(tmp_dir, 'out', 'artifacts')
      os.makedirs(artifacts_path)
      runner = self._create_runner(workspace=tmp_dir)
      self.assertTrue(runner.initialize())
      mock_log_error.assert_not_called()
      self.assertTrue(os.path.isdir(artifacts_path))

  @mock.patch('utils.get_fuzz_targets')
  @mock.patch('logging.error')
  def test_initialize_no_artifacts(self, mock_log_error, mock_get_fuzz_targets):
    """Tests initialize with no artifacts dir (the expected setting)."""
    mock_get_fuzz_targets.return_value = ['fuzz-target']
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      runner = self._create_runner(workspace=tmp_dir)
      self.assertTrue(runner.initialize())
      mock_log_error.assert_not_called()
      self.assertTrue(os.path.isdir(os.path.join(tmp_dir, 'out', 'artifacts')))

  def test_initialize_no_fuzz_targets(self):
    """Tests initialize with no fuzz targets."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.makedirs(out_path)
      expected_error_args = ('No fuzz targets were found in out directory: %s.',
                             out_path)
      self._test_initialize_fail(expected_error_args, workspace=tmp_dir)


class CiFuzzTargetRunnerTest(fake_filesystem_unittest.TestCase):
  """Tests that CiFuzzTargetRunner works as intended."""

  def setUp(self):
    self.setUpPyfakefs()

  @mock.patch('clusterfuzz_deployment.OSSFuzz.upload_crashes')
  @mock.patch('utils.get_fuzz_targets')
  @mock.patch('run_fuzzers.CiFuzzTargetRunner.run_fuzz_target')
  @mock.patch('run_fuzzers.CiFuzzTargetRunner.create_fuzz_target_obj')
  def test_run_fuzz_targets_quits(self, mock_create_fuzz_target_obj,
                                  mock_run_fuzz_target, mock_get_fuzz_targets,
                                  mock_upload_crashes):
    """Tests that run_fuzz_targets quits on the first crash it finds."""
    workspace = 'workspace'
    out_path = os.path.join(workspace, 'build-out')
    self.fs.create_dir(out_path)
    config = test_helpers.create_run_config(
        fuzz_seconds=FUZZ_SECONDS,
        workspace=workspace,
        oss_fuzz_project_name=EXAMPLE_PROJECT)
    runner = run_fuzzers.CiFuzzTargetRunner(config)

    mock_get_fuzz_targets.return_value = ['target1', 'target2']
    runner.initialize()
    testcase = os.path.join(workspace, 'testcase')
    self.fs.create_file(testcase)
    stacktrace = 'stacktrace'
    corpus_dir = 'corpus'
    self.fs.create_dir(corpus_dir)
    mock_run_fuzz_target.return_value = fuzz_target.FuzzResult(
        testcase, stacktrace, corpus_dir)
    magic_mock = mock.MagicMock()
    magic_mock.target_name = 'target1'
    mock_create_fuzz_target_obj.return_value = magic_mock
    self.assertTrue(runner.run_fuzz_targets())
    self.assertEqual(mock_run_fuzz_target.call_count, 1)
    self.assertEqual(mock_upload_crashes.call_count, 1)


class BatchFuzzTargetRunnerTest(fake_filesystem_unittest.TestCase):
  """Tests that BatchFuzzTargetRunnerTest works as intended."""
  WORKSPACE = 'workspace'
  STACKTRACE = 'stacktrace'
  CORPUS_DIR = 'corpus'

  def setUp(self):
    self.setUpPyfakefs()
    out_dir = os.path.join(self.WORKSPACE, 'build-out')
    self.fs.create_dir(out_dir)
    self.testcase1 = os.path.join(out_dir, 'testcase-aaa')
    self.fs.create_file(self.testcase1)
    self.testcase2 = os.path.join(out_dir, 'testcase-bbb')
    self.fs.create_file(self.testcase2)
    self.config = test_helpers.create_run_config(fuzz_seconds=FUZZ_SECONDS,
                                                 workspace=self.WORKSPACE,
                                                 cfl_platform='github')

  @mock.patch('utils.get_fuzz_targets', return_value=['target1', 'target2'])
  @mock.patch('clusterfuzz_deployment.ClusterFuzzLite.upload_crashes')
  @mock.patch('run_fuzzers.BatchFuzzTargetRunner.run_fuzz_target')
  @mock.patch('run_fuzzers.BatchFuzzTargetRunner.create_fuzz_target_obj')
  def test_run_fuzz_targets_quits(self, mock_create_fuzz_target_obj,
                                  mock_run_fuzz_target, mock_upload_crashes, _):
    """Tests that run_fuzz_targets doesn't quit on the first crash it finds."""
    runner = run_fuzzers.BatchFuzzTargetRunner(self.config)
    runner.initialize()

    call_count = 0

    def mock_run_fuzz_target_impl(_):
      nonlocal call_count
      if call_count == 0:
        testcase = self.testcase1
      elif call_count == 1:
        testcase = self.testcase2
      assert call_count != 2
      call_count += 1
      if not os.path.exists(self.CORPUS_DIR):
        self.fs.create_dir(self.CORPUS_DIR)
      return fuzz_target.FuzzResult(testcase, self.STACKTRACE, self.CORPUS_DIR)

    mock_run_fuzz_target.side_effect = mock_run_fuzz_target_impl
    magic_mock = mock.MagicMock()
    magic_mock.target_name = 'target1'
    mock_create_fuzz_target_obj.return_value = magic_mock
    self.assertTrue(runner.run_fuzz_targets())
    self.assertEqual(mock_run_fuzz_target.call_count, 2)
    self.assertEqual(mock_upload_crashes.call_count, 1)


class GetCoverageTargetsTest(unittest.TestCase):
  """Tests for get_coverage_fuzz_targets."""

  def test_get_fuzz_targets(self):
    """Tests that get_coverage_fuzz_targets returns expected targets."""
    with tempfile.TemporaryDirectory() as temp_dir:
      # Setup.
      fuzz_target_path = os.path.join(temp_dir, 'fuzz-target')
      with open(fuzz_target_path, 'w') as file_handle:
        file_handle.write('')
      fuzz_target_st = os.stat(fuzz_target_path)
      os.chmod(fuzz_target_path, fuzz_target_st.st_mode | stat.S_IEXEC)
      non_fuzz_target1 = os.path.join(temp_dir, 'non-fuzz-target1')
      with open(non_fuzz_target1, 'w') as file_handle:
        file_handle.write('LLVMFuzzerTestOneInput')
      subdir = os.path.join(temp_dir, 'subdir')
      os.mkdir(subdir)
      non_fuzz_target2 = os.path.join(subdir, 'non-fuzz-target1')
      with open(non_fuzz_target2, 'w') as file_handle:
        file_handle.write('LLVMFuzzerTestOneInput')

      self.assertEqual(run_fuzzers.get_coverage_fuzz_targets(temp_dir),
                       [fuzz_target_path])


@unittest.skip('TODO(metzman): Fix this test')
@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class CoverageReportIntegrationTest(unittest.TestCase):
  """Integration tests for coverage reports."""
  SANITIZER = 'coverage'

  def setUp(self):
    test_helpers.patch_environ(self, runner=True)

  @mock.patch('filestore.github_actions._upload_artifact_with_upload_js')
  def test_coverage_report(self, _):
    """Tests generation of coverage reports end-to-end, from building to
    generation."""

    with test_helpers.docker_temp_dir() as temp_dir:
      shared = os.path.join(temp_dir, 'shared')
      os.mkdir(shared)
      copy_command = ('cp -r /opt/code_coverage /shared && '
                      'cp $(which llvm-profdata) /shared && '
                      'cp $(which llvm-cov) /shared')
      assert helper.docker_run([
          '-v', f'{shared}:/shared', 'gcr.io/oss-fuzz-base/base-runner', 'bash',
          '-c', copy_command
      ])

      os.environ['CODE_COVERAGE_SRC'] = os.path.join(shared, 'code_coverage')
      os.environ['PATH'] += os.pathsep + shared
      # Do coverage build.
      build_config = test_helpers.create_build_config(
          oss_fuzz_project_name=EXAMPLE_PROJECT,
          project_repo_name='oss-fuzz',
          workspace=temp_dir,
          git_sha='0b95fe1039ed7c38fea1f97078316bfc1030c523',
          base_commit='da0746452433dc18bae699e355a9821285d863c8',
          sanitizer=self.SANITIZER,
          cfl_platform='github',
          # Needed for test not to fail because of permissions issues.
          bad_build_check=False)
      self.assertTrue(build_fuzzers.build_fuzzers(build_config))

      # TODO(metzman): Get rid of this here and make 'compile' do this.
      chmod_command = ('chmod -R +r /out && '
                       'find /out -type d -exec chmod +x {} +')

      assert helper.docker_run([
          '-v', f'{os.path.join(temp_dir, "build-out")}:/out',
          'gcr.io/oss-fuzz-base/base-builder', 'bash', '-c', chmod_command
      ])

      # Generate report.
      run_config = test_helpers.create_run_config(fuzz_seconds=FUZZ_SECONDS,
                                                  workspace=temp_dir,
                                                  sanitizer=self.SANITIZER,
                                                  mode='coverage',
                                                  cfl_platform='github')
      result = run_fuzzers.run_fuzzers(run_config)
      self.assertEqual(result, run_fuzzers.RunFuzzersResult.NO_BUG_FOUND)
      expected_summary_path = os.path.join(
          TEST_DATA_PATH, 'example_coverage_report_summary.json')
      with open(expected_summary_path) as file_handle:
        expected_summary = json.loads(file_handle.read())
        actual_summary_path = os.path.join(temp_dir, 'cifuzz-coverage',
                                           'report', 'linux', 'summary.json')
      with open(actual_summary_path) as file_handle:
        actual_summary = json.loads(file_handle.read())
      self.assertEqual(expected_summary, actual_summary)


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class RunAddressFuzzersIntegrationTest(RunFuzzerIntegrationTestMixin,
                                       unittest.TestCase):
  """Integration tests for build_fuzzers with an ASAN build."""

  BUILD_DIR_NAME = 'cifuzz-latest-build'

  def test_new_bug_found(self):
    """Tests run_fuzzers with a valid ASAN build."""
    # Set the first return value to True, then the second to False to
    # emulate a bug existing in the current PR but not on the downloaded
    # OSS-Fuzz build.
    with mock.patch('fuzz_target.FuzzTarget.is_reproducible',
                    side_effect=[True, False]):
      with tempfile.TemporaryDirectory() as tmp_dir:
        workspace = os.path.join(tmp_dir, 'workspace')
        shutil.copytree(TEST_DATA_PATH, workspace)
        config = test_helpers.create_run_config(
            fuzz_seconds=FUZZ_SECONDS,
            workspace=workspace,
            oss_fuzz_project_name=EXAMPLE_PROJECT)
        result = run_fuzzers.run_fuzzers(config)
        self.assertEqual(result, run_fuzzers.RunFuzzersResult.BUG_FOUND)

  @mock.patch('fuzz_target.FuzzTarget.is_reproducible',
              side_effect=[True, True])
  def test_old_bug_found(self, _):
    """Tests run_fuzzers with a bug found in OSS-Fuzz before."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      workspace = os.path.join(tmp_dir, 'workspace')
      shutil.copytree(TEST_DATA_PATH, workspace)
      config = test_helpers.create_run_config(
          fuzz_seconds=FUZZ_SECONDS,
          workspace=workspace,
          oss_fuzz_project_name=EXAMPLE_PROJECT)
      result = run_fuzzers.run_fuzzers(config)
      self.assertEqual(result, run_fuzzers.RunFuzzersResult.NO_BUG_FOUND)

  def test_invalid_build(self):
    """Tests run_fuzzers with an invalid ASAN build."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'build-out')
      os.mkdir(out_path)
      config = test_helpers.create_run_config(
          fuzz_seconds=FUZZ_SECONDS,
          workspace=tmp_dir,
          oss_fuzz_project_name=EXAMPLE_PROJECT)
      result = run_fuzzers.run_fuzzers(config)
    self.assertEqual(result, run_fuzzers.RunFuzzersResult.ERROR)


class GetFuzzTargetRunnerTest(unittest.TestCase):
  """Tests for get_fuzz_fuzz_target_runner."""

  @parameterized.parameterized.expand([
      ('batch', run_fuzzers.BatchFuzzTargetRunner),
      ('code-change', run_fuzzers.CiFuzzTargetRunner),
      ('coverage', run_fuzzers.CoverageTargetRunner)
  ])
  def test_get_fuzz_target_runner(self, mode, fuzz_target_runner_cls):
    """Tests that get_fuzz_target_runner returns the correct runner based on the
    specified mode."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      run_config = test_helpers.create_run_config(
          fuzz_seconds=FUZZ_SECONDS,
          workspace=tmp_dir,
          oss_fuzz_project_name='example',
          mode=mode)
      runner = run_fuzzers.get_fuzz_target_runner(run_config)
      self.assertTrue(isinstance(runner, fuzz_target_runner_cls))


if __name__ == '__main__':
  unittest.main()
