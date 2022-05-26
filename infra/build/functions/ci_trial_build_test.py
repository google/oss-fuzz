"""Tests for ci_trial_build.py."""
import sys
import unittest
from unittest import mock

import ci_trial_build

class GetLatestGCBrunCommandTest(unittest.TestCase):
  """Tests for get_latest_gcbrun_command."""

  def test_command_parsing(self):
    """Tests that commands from GitHub comments are parsed properly."""
    mock_comment = mock.MagicMock()
    mock_comment.body = (f'/gcbrun {sys.argv[0]} aiohttp --sanitizer '
                         'coverage address --fuzzing-engine libfuzzer')
    comments = [
        mock_comment
    ]
    expected_command = ['aiohttp', '--sanitizer', 'coverage', 'address',
                        '--fuzzing-engine', 'libfuzzer']
    actual_command = ci_trial_build.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)

  def test_last_comment(self):
    """Tests that the last comment from the GitHub PR is considered the
    command."""
    mock_comment_1 = mock.MagicMock()
    mock_comment_1.body = (f'/gcbrun {sys.argv[0]} aiohttp --sanitizer '
                           'coverage address --fuzzing-engine libfuzzer')
    mock_comment_2 = mock.MagicMock()
    mock_comment_2.body = (f'/gcbrun {sys.argv[0]} skcms --sanitizer '
                           'coverage address --fuzzing-engine libfuzzer')
    comments = [
        mock_comment_1,
        mock_comment_2
    ]
    expected_command = ['skcms', '--sanitizer', 'coverage', 'address',
                        '--fuzzing-engine', 'libfuzzer']
    actual_command = ci_trial_build.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)
