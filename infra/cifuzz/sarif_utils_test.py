# Copyright 2023 Google LLC
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
"""Tests for sarif_utils.py"""
import os
import unittest
from unittest import mock

import sarif_utils

CRASH_INFO_FILELINE = 403

TEST_DATA = os.path.join(os.path.dirname(__file__), 'test_data')


class GetSarifDataTest(unittest.TestCase):
  """Tests for get_sarif_data."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_get_sarif_data_none(self):
    """Tests get_sarif_data when there was no crash."""
    self.assertEqual(sarif_utils.get_sarif_data(None, '/root/target'),
                     sarif_utils.SARIF_DATA)

  def test_ordinary_case(self):
    stacktrace_filename = os.path.join(TEST_DATA,
                                       'sarif_utils_systemd_stack.txt')
    with open(stacktrace_filename, 'r') as fp:
      stacktrace = fp.read()
    expected_result = {
        'level': 'error',
        'message': {
            'text': 'Heap-buffer-overflow\nREAD 4'
        },
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {
                    'uri': 'src/core/fuzz-unit-file.c',
                    'index': 0
                },
                'region': {
                    'startLine': 30,
                    # We don't have this granualarity fuzzing.
                    'startColumn': 1,
                }
            }
        }],
        'ruleId': 'heap-buffer-overflow',
        'ruleIndex': 2
    }
    actual_result = sarif_utils.get_sarif_data(
        stacktrace, '/root/target')['runs'][0]['results'][0]
    self.assertEqual(actual_result, expected_result)

  def test_llvmfuzzertestoneinput_case(self):
    stacktrace_filename = os.path.join(TEST_DATA,
                                       'sarif_utils_only_llvmfuzzer_stack.txt')
    with open(stacktrace_filename, 'r') as fp:
      stacktrace = fp.read()
    actual_result = sarif_utils.get_sarif_data(
        stacktrace, '/root/target')['runs'][0]['results']
    self.assertEqual(actual_result, [])

  def test_msan(self):
    """Tests that MSAN stacktraces don't exception."""
    stacktrace_filename = os.path.join(TEST_DATA, 'sarif_utils_msan_stack.txt')
    with open(stacktrace_filename, 'r') as fp:
      stacktrace = fp.read()

    actual_result = sarif_utils.get_sarif_data(stacktrace, '/root/target')


class RedactSrcPathTest(unittest.TestCase):
  """Tests for redact_src_path."""

  def test_redact_src_path(self):
    """Tests redact_src_path."""
    path = '/src/src-repo/subdir/file'
    self.assertEqual(sarif_utils.redact_src_path(path), 'subdir/file')


def _get_mock_crash_info():
  """Returns a mock crash_info to be used in tests."""
  stack_frame = mock.MagicMock()
  stack_frame.filename = '/src/repo-dir/sub/vuln.cc'
  stack_frame.function_name = 'vuln_func'
  stack_frame.fileline = CRASH_INFO_FILELINE
  crash1_frames = [stack_frame, stack_frame]
  frames = [crash1_frames]
  crash_info = mock.MagicMock()
  crash_info.frames = frames
  crash_info.crash_state = 'vuln_func\nvuln_func0\nvuln_func1'
  return crash_info


class GetErrorSourceInfoTest(unittest.TestCase):
  """Tests for get_error_source_info."""

  def test_redact_src_path(self):
    """Tests that get_error_source_info finds the right source info."""
    crash_info = _get_mock_crash_info()
    source_info = sarif_utils.get_error_source_info(crash_info)
    expected_source_info = ('sub/vuln.cc', CRASH_INFO_FILELINE)
    self.assertEqual(source_info, expected_source_info)


class GetRuleIndexTest(unittest.TestCase):
  """Tests for get_rule_index."""
  CRASH_INFO_CRASH_TYPE = 'Heap-use-after-free READ 8'

  def test_get_rule_index(self):
    """Tests that get_rule_index finds the right rule index."""
    index = sarif_utils.get_rule_index(self.CRASH_INFO_CRASH_TYPE)
    self.assertEqual(sarif_utils.SARIF_RULES[index]['id'],
                     'heap-use-after-free')
    self.assertEqual(sarif_utils.get_rule_index('no-crashes'), 0)
