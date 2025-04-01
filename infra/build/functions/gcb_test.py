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
"""Tests for gcb.py."""
import unittest
from unittest import mock

import gcb


class GetLatestGCBrunCommandTest(unittest.TestCase):
  """Tests for get_latest_gcbrun_command."""

  def test_command_parsing(self):
    """Tests that commands from GitHub comments are parsed properly."""
    mock_comment = mock.MagicMock()
    mock_comment.body = ('/gcbrun trial_build.py aiohttp --sanitizer '
                         'coverage address --fuzzing-engine libfuzzer')
    comments = [mock_comment]
    expected_command = [
        'trial_build.py', 'aiohttp', '--sanitizer', 'coverage', 'address',
        '--fuzzing-engine', 'libfuzzer'
    ]
    actual_command = gcb.get_latest_gcbrun_command(comments)
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
        'trial_build.py', 'skcms', '--sanitizer', 'coverage', 'address',
        '--fuzzing-engine', 'libfuzzer'
    ]
    actual_command = gcb.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)

  def test_oss_fuzz_on_demand_command_parsing(self):
    """Tests that the OSS-Fuzz on demand commands from GitHub comments are
    parsed properly."""
    mock_comment = mock.MagicMock()
    mock_comment.body = ('/gcbrun oss_fuzz_on_demand.py aiohttp --sanitizer '
                         'coverage address --fuzzing-engine libfuzzer')
    comments = [mock_comment]
    expected_command = [
        'oss_fuzz_on_demand.py', 'aiohttp', '--sanitizer', 'coverage',
        'address', '--fuzzing-engine', 'libfuzzer'
    ]
    actual_command = gcb.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)


class ExecCommandFromGithubTest(unittest.TestCase):
  """Tests for exec_command_from_github."""

  def test_exec_command(self):
    """Tests if exec_command_from_github is generating the correct command."""
    test_cases = [
        {
            "comments": [('/gcbrun oss_fuzz_on_demand.py aiohttp --sanitizer'
                          'coverage address --fuzzing-engine libfuzzer')],
            "latest_command": [
                'oss_fuzz_on_demand.py', 'aiohttp', '--sanitizer', 'coverage',
                'address', '--fuzzing-engine', 'libfuzzer'
            ],
            "expected_command": [
                'aiohttp', '--sanitizer', 'coverage', 'address',
                '--fuzzing-engine', 'libfuzzer', '--repo', 'test_repo',
                '--branch', 'test_branch'
            ],
            "trial_build_called": False,
        },
        {
            "comments": ['/gcbrun trial_build.py my_project'],
            "latest_command": ['trial_build.py', 'my_project'],
            "expected_command": ([
                'my_project', '--repo', 'test_repo', '--branch', 'test_branch'
            ]),
            "trial_build_called": True,
        },
        {
            "comments": ['/gcbrun trial_build.py my_project'],
            "latest_command": None,
            "expected_command": ([
                'my_project', '--repo', 'test_repo', '--branch', 'test_branch'
            ]),
            "trial_build_called": True,
        },
    ]
    for i, test_case in enumerate(test_cases):
      with self.subTest(i=i):
        with mock.patch('gcb.get_comments',
                        return_value=test_case["comments"]), \
             mock.patch('gcb.get_latest_gcbrun_command',
                        return_value=test_case["latest_command"]), \
             mock.patch('oss_fuzz_on_demand.oss_fuzz_on_demand_main') as (
                 mock_oss_fuzz_on_demand), \
             mock.patch('trial_build.trial_build_main') as (
                 mock_trial_build_trial_build_main):

          gcb.exec_command_from_github(0, "test_repo", "test_branch")

          if test_case["latest_command"] == None:
            mock_trial_build_trial_build_main.assert_not_called()
            mock_oss_fuzz_on_demand.assert_not_called()

          else:
            if test_case["trial_build_called"]:
              mock_trial_build_trial_build_main.assert_called_once_with(
                  test_case["expected_command"], local_base_build=False)
              mock_oss_fuzz_on_demand.assert_not_called()
            else:
              mock_trial_build_trial_build_main.assert_not_called()
              mock_oss_fuzz_on_demand.assert_called_once_with(
                  test_case["expected_command"])
