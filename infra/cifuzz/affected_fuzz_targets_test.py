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
"""Tests for affected_fuzz_targets.py"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

import parameterized

import affected_fuzz_targets
import clusterfuzz_deployment
import get_coverage
import test_helpers
import workspace_utils

# pylint: disable=protected-access

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

EXAMPLE_FILE_CHANGED = 'test.txt'

TEST_DATA_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'test_data', 'build-out')


class RemoveUnaffectedFuzzTargetsTest(unittest.TestCase):
  """Tests remove_unaffected_fuzzers."""

  TEST_FUZZER_1 = os.path.join(TEST_DATA_OUT_PATH, 'example_crash_fuzzer')
  TEST_FUZZER_2 = os.path.join(TEST_DATA_OUT_PATH, 'example_nocrash_fuzzer')

  # yapf: disable
  @parameterized.parameterized.expand([
      # Tests specific affected fuzzers are kept.
      ([[EXAMPLE_FILE_CHANGED], None], 2,),

      # Tests specific affected fuzzer is kept.
      ([[EXAMPLE_FILE_CHANGED], ['not/a/real/file']], 1),

      # Tests all fuzzers are kept if none are deemed affected.
      ([None, None], 2),

      # Tests that multiple fuzzers are kept if multiple fuzzers are affected.
      ([[EXAMPLE_FILE_CHANGED], [EXAMPLE_FILE_CHANGED]], 2),
      ])
  # yapf: enable
  def test_remove_unaffected_fuzz_targets(self, side_effect, expected_dir_len):
    """Tests that remove_unaffected_fuzzers has the intended effect."""
    config = test_helpers.create_run_config(
        cfl_platform='github',
        oss_fuzz_project_name=EXAMPLE_PROJECT,
        workspace='/workspace')
    workspace = workspace_utils.Workspace(config)
    deployment = clusterfuzz_deployment.get_clusterfuzz_deployment(
        config, workspace)
    # We can't use fakefs in this test because this test executes
    # utils.is_fuzz_target_local. This function relies on the executable bit
    # being set, which doesn't work properly in fakefs.
    with tempfile.TemporaryDirectory() as tmp_dir, mock.patch(
        'get_coverage.OSSFuzzCoverage.get_files_covered_by_target'
    ) as mock_get_files:
      with mock.patch('get_coverage._get_oss_fuzz_fuzzer_stats_dir_url',
                      return_value=1):
        mock_get_files.side_effect = side_effect
        shutil.copy(self.TEST_FUZZER_1, tmp_dir)
        shutil.copy(self.TEST_FUZZER_2, tmp_dir)

        affected_fuzz_targets.remove_unaffected_fuzz_targets(
            deployment, tmp_dir, [EXAMPLE_FILE_CHANGED], '')
        self.assertEqual(expected_dir_len, len(os.listdir(tmp_dir)))


class IsFuzzTargetAffectedTest(unittest.TestCase):
  """Tests for is_fuzz_target_affected."""

  def setUp(self):
    self.fuzz_target_path = '/fuzz_target'

  def test_relative_paths(self):
    """Tests that is_fuzz_target_affected works as intended when the covered
    files are relative paths."""
    with mock.patch.object(
        get_coverage.FilesystemCoverage,
        'get_files_covered_by_target',
    ) as get_files_covered_by_target:
      get_files_covered_by_target.return_value = [
          '/work/build/../../src/systemd/src/basic/alloc-util.c'
      ]
      coverage = get_coverage.FilesystemCoverage('/', '/')

      self.assertTrue(
          affected_fuzz_targets.is_fuzz_target_affected(
              coverage, self.fuzz_target_path,
              ['/src/systemd/src/basic/alloc-util.c']))


if __name__ == '__main__':
  unittest.main()
