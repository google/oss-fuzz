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

COMMIT_SHA = '0123456789abcdef0123456789abcdef01234567'


def _make_comment(body, author_association='COLLABORATOR'):
  """Returns a mock GitHub comment."""
  comment = mock.MagicMock()
  comment.body = body
  comment.author_association = author_association
  return comment


class GetLatestGCBrunCommandTest(unittest.TestCase):
  """Tests for get_latest_gcbrun_command."""

  def test_command_parsing(self):
    """Tests that commands from GitHub comments are parsed properly."""
    mock_comment = _make_comment('/gcbrun trial_build.py aiohttp --sanitizer '
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
    mock_comment_1 = _make_comment(
        '/gcbrun trial_build.py aiohttp --sanitizer '
        'coverage address --fuzzing-engine libfuzzer')
    mock_comment_2 = _make_comment(
        '/gcbrun trial_build.py skcms --sanitizer '
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
    mock_comment = _make_comment(
        '/gcbrun oss_fuzz_on_demand.py aiohttp --sanitizer '
        'coverage address --fuzzing-engine libfuzzer')
    comments = [mock_comment]
    expected_command = [
        'oss_fuzz_on_demand.py', 'aiohttp', '--sanitizer', 'coverage',
        'address', '--fuzzing-engine', 'libfuzzer'
    ]
    actual_command = gcb.get_latest_gcbrun_command(comments)
    self.assertEqual(expected_command, actual_command)

  def test_ignores_untrusted_authors(self):
    """Tests that a later command from someone without write access doesn't
    replace the command from a collaborator."""
    collaborator_comment = _make_comment(
        '/gcbrun trial_build.py swift-nio --sanitizers address')
    outsider_comment = _make_comment(
        '/gcbrun trial_build.py --repo https://github.com/evil/repo '
        '--branch evil --sanitizers indexer --force-build -- zlib',
        author_association='NONE')
    contributor_skip = _make_comment('/gcbrun skip',
                                     author_association='CONTRIBUTOR')
    comments = [collaborator_comment, outsider_comment, contributor_skip]
    self.assertEqual(['trial_build.py', 'swift-nio', '--sanitizers', 'address'],
                     gcb.get_latest_gcbrun_command(comments))

  def test_missing_body_and_user(self):
    """Tests that comments without a body or author don't crash the build."""
    collaborator_comment = _make_comment('/gcbrun trial_build.py zlib')
    empty_comment = _make_comment(None)
    deleted_user_comment = _make_comment('/gcbrun trial_build.py curl',
                                         author_association='NONE')
    deleted_user_comment.user = None
    comments = [collaborator_comment, empty_comment, deleted_user_comment]
    self.assertEqual(['trial_build.py', 'zlib'],
                     gcb.get_latest_gcbrun_command(comments))

  def test_only_untrusted_authors(self):
    """Tests that commands from people without write access are ignored."""
    comments = [
        _make_comment('/gcbrun trial_build.py zlib',
                      author_association=association)
        for association in ('NONE', 'CONTRIBUTOR', 'FIRST_TIME_CONTRIBUTOR')
    ]
    self.assertIsNone(gcb.get_latest_gcbrun_command(comments))


class ExecCommandFromGithubTest(unittest.TestCase):
  """Tests for exec_command_from_github."""

  @mock.patch(
      'os.environ', {
          'PULL_REQUEST_NUMBER': '0',
          'BRANCH': 'test_branch',
          'REPO': 'test_repo',
          'COMMIT_SHA': COMMIT_SHA
      })
  def test_exec_command(self):
    """Tests if exec_command_from_github is generating the correct command."""
    test_cases = [
        {
            "comments": ['/gcbrun trial_build.py my_project'],
            "latest_command": ['trial_build.py', 'my_project'],
            "expected_command": ['my_project', '--version-tag', 'latest'],
            "trial_build_called": True,
        },
        {
            "comments": ['/gcbrun trial_build.py my_project'],
            "latest_command": None,
            "expected_command": ['my_project', '--version-tag', 'latest'],
            "trial_build_called": True,
        },
    ]
    for i, test_case in enumerate(test_cases):
      with self.subTest(i=i):
        with mock.patch(
            'gcb.get_comments', return_value=test_case["comments"]), mock.patch(
                'gcb.get_latest_gcbrun_command',
                return_value=test_case["latest_command"]), mock.patch(
                    'trial_build.trial_build_main') as (
                        mock_trial_build_trial_build_main):

          gcb.exec_command_from_github(['--version-tag', 'latest'])

          if test_case["latest_command"] is None:
            mock_trial_build_trial_build_main.assert_not_called()
          else:
            mock_trial_build_trial_build_main.assert_called_once_with(
                test_case["expected_command"],
                local_base_build=False,
                source=('test_repo', 'test_branch', COMMIT_SHA))

  @mock.patch(
      'os.environ', {
          'PULL_REQUEST_NUMBER': '0',
          'BRANCH': 'test_branch',
          'REPO': 'test_repo',
          'COMMIT_SHA': COMMIT_SHA
      })
  @mock.patch('gcb.get_comments', return_value=[])
  @mock.patch('gcb.get_latest_gcbrun_command',
              return_value=[
                  'oss_fuzz_on_demand.py', 'aiohttp', '--fuzzing-engine',
                  'libfuzzer'
              ])
  @mock.patch('oss_fuzz_on_demand.oss_fuzz_on_demand_main')
  @mock.patch('trial_build.trial_build_main')
  def test_oss_fuzz_on_demand_disabled(self, mock_trial_build_main,
                                       mock_oss_fuzz_on_demand_main,
                                       mock_get_latest_gcbrun_command,
                                       mock_gcb_get_comments):
    """Tests that OSS-Fuzz on Demand can't run from PR comments."""
    del mock_get_latest_gcbrun_command
    del mock_gcb_get_comments
    self.assertFalse(gcb.exec_command_from_github([]))
    mock_trial_build_main.assert_not_called()
    mock_oss_fuzz_on_demand_main.assert_not_called()

  @mock.patch('gcb.get_comments', return_value=[])
  @mock.patch('gcb.get_latest_gcbrun_command',
              return_value=['trial_build.py', 'my_project'])
  @mock.patch('trial_build.trial_build_main')
  def test_trial_build_needs_commit(self, mock_trial_build_main,
                                    mock_get_latest_gcbrun_command,
                                    mock_gcb_get_comments):
    """Tests that trial builds don't fall back to the tip of the branch when
    the commit is missing or invalid."""
    del mock_get_latest_gcbrun_command
    del mock_gcb_get_comments
    env = {
        'PULL_REQUEST_NUMBER': '0',
        'BRANCH': 'test_branch',
        'REPO': 'test_repo',
    }
    for commit in (None, '', 'test_branch', COMMIT_SHA[:7], COMMIT_SHA + '\n'):
      with self.subTest(commit=commit):
        test_env = dict(env)
        if commit is not None:
          test_env['COMMIT_SHA'] = commit
        with mock.patch('os.environ', test_env):
          self.assertFalse(gcb.exec_command_from_github([]))
    mock_trial_build_main.assert_not_called()
