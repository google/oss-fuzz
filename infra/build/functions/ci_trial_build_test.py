# Copyright 2022 Google LLC
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
#
################################################################################
"""Tests for ci_trial_build.py."""
import unittest
from unittest import mock

import ci_trial_build


class GetLatestGCBrunCommandTest(unittest.TestCase):
  """Tests for get_latest_gcbrun_command."""

  def test_command_parsing(self):
    """Tests that commands from GitHub comments are parsed properly."""
    mock_comment = mock.MagicMock()
    mock_comment.body = ('/gcbrun trial_build.py aiohttp --sanitizer '
                         'coverage address --fuzzing-engine libfuzzer')
    comments = [mock_comment]
    expected_command = [
        'aiohttp', '--sanitizer', 'coverage', 'address', '--fuzzing-engine',
        'libfuzzer'
    ]
    actual_command = ci_trial_build.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)

  def test_last_comment(self):
    """Tests that the last comment from the GitHub PR is considered the
    command."""
    mock_comment_1 = mock.MagicMock()
    mock_comment_1.body = ('/gcbrun trial_build.py aiohttp --sanitizer '
                           'coverage address --fuzzing-engine libfuzzer')
    mock_comment_2 = mock.MagicMock()
    mock_comment_2.body = ('/gcbrun trial_build.py skcms --sanitizer '
                           'coverage address --fuzzing-engine libfuzzer')
    comments = [mock_comment_1, mock_comment_2]
    expected_command = [
        'skcms', '--sanitizer', 'coverage', 'address', '--fuzzing-engine',
        'libfuzzer'
    ]
    actual_command = ci_trial_build.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)
