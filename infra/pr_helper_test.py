#!/usr/bin/env python
# Copyright 2026 Google LLC
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
"""PR helper env variable injection and URL sanitization tests."""

import os
import re
import tempfile
import unittest
from unittest import mock

import pr_helper

# pylint: disable=protected-access


def _parse_github_env(content):
  """Parses a GITHUB_ENV file and returns a dict of env var names to values.

  Supports both KEY=value and KEY<<DELIMITER formats.
  """
  env_vars = {}
  lines = content.split('\n')
  i = 0
  while i < len(lines):
    line = lines[i]
    if not line:
      i += 1
      continue

    # Check for delimiter format: NAME<<DELIMITER
    delim_match = re.match(r'^([A-Z_]+)<<(.+)$', line)
    if delim_match:
      name = delim_match.group(1)
      delimiter = delim_match.group(2)
      value_lines = []
      i += 1
      while i < len(lines) and lines[i] != delimiter:
        value_lines.append(lines[i])
        i += 1
      env_vars[name] = '\n'.join(value_lines)
      i += 1  # skip the closing delimiter
      continue

    # Check for simple KEY=value format
    eq_match = re.match(r'^([A-Z_]+)=(.*)$', line)
    if eq_match:
      env_vars[eq_match.group(1)] = eq_match.group(2)

    i += 1

  return env_vars


class SaveEnvTest(unittest.TestCase):
  """Verify save_env blocks env variable injection via GITHUB_ENV."""

  def setUp(self):
    self.env_file = tempfile.NamedTemporaryFile(mode='w',
                                                delete=False,
                                                suffix='.env')
    self.env_file.close()
    self.patcher = mock.patch.dict(os.environ,
                                   {'GITHUB_ENV': self.env_file.name})
    self.patcher.start()

  def tearDown(self):
    self.patcher.stop()
    os.unlink(self.env_file.name)

  def _read_env_file(self):
    with open(self.env_file.name, 'r', encoding='utf-8') as env_file:
      return env_file.read()

  def test_save_env_basic(self):
    """Normal values produce correct key=value output."""
    pr_helper.save_env('hello world', True, False)
    env_vars = _parse_github_env(self._read_env_file())
    self.assertEqual(env_vars['MESSAGE'], 'hello world')
    self.assertEqual(env_vars['IS_READY_FOR_MERGE'], 'True')
    self.assertEqual(env_vars['IS_INTERNAL'], 'False')

  def test_save_env_newline_injection_blocked(self):
    """Newlines in message must not inject extra env vars."""
    malicious = 'hello\nGITHUB_API_URL=https://evil.com'
    pr_helper.save_env(malicious, True, False)
    env_vars = _parse_github_env(self._read_env_file())
    # The injected env var must NOT appear as a separate variable.
    self.assertNotIn('GITHUB_API_URL', env_vars)
    # There must be exactly 3 env vars.
    self.assertEqual(len(env_vars), 3)

  def test_save_env_carriage_return_injection_blocked(self):
    """Carriage returns (\\r\\n, \\r) must not enable injection."""
    pr_helper.save_env('a\r\nEVIL=1\rb', True, False)
    env_vars = _parse_github_env(self._read_env_file())
    self.assertNotIn('EVIL', env_vars)
    self.assertEqual(len(env_vars), 3)

  def test_save_env_injection_via_all_fields(self):
    """Injection via is_ready_for_merge and is_internal is blocked."""
    pr_helper.save_env('msg', 'True\nEVIL=1', 'False\nEVIL=2')
    env_vars = _parse_github_env(self._read_env_file())
    self.assertNotIn('EVIL', env_vars)
    self.assertEqual(len(env_vars), 3)

  def test_save_env_none_values(self):
    """None values (internal member path) are written safely."""
    pr_helper.save_env(None, None, True)
    env_vars = _parse_github_env(self._read_env_file())
    self.assertEqual(env_vars['MESSAGE'], 'None')
    self.assertEqual(env_vars['IS_INTERNAL'], 'True')

  def test_save_env_full_attack_scenario(self):
    """Reproduces the reported attack: malicious main_repo
    exfiltrating GITHUB_TOKEN."""
    attack_url = ('https://github.com/attacker/repo\n'
                  'GITHUB_API_URL=https://evil.com\nx=1')
    message = (f'user is integrating a new project:<br/>'
               f'- Main repo: {attack_url}<br/>'
               f' - Criticality score: N/A<br/>')
    pr_helper.save_env(message, False, False)
    env_vars = _parse_github_env(self._read_env_file())
    self.assertNotIn('GITHUB_API_URL', env_vars)
    self.assertNotIn('x', env_vars)
    self.assertEqual(len(env_vars), 3)


class SanitizeRepoUrlTest(unittest.TestCase):
  """Verify _sanitize_repo_url strips control chars and validates scheme."""

  def test_valid_url_unchanged(self):
    """Valid https, http, git://, and git@ URLs pass through unchanged."""
    urls = [
        'https://github.com/google/oss-fuzz',
        'https://github.com/abseil/abseil-cpp.git',
        'https://bitbucket.org/nielsenb/aniso8601',
        'https://chromium.googlesource.com/angle/angle',
        'https://gitbox.apache.org/repos/asf/commons-io.git',
        'https://github.com/apache/tika/',
        'http://github.com/matthewwithanm/python-markdownify',
        'git://git.gnupg.org/gnupg.git',
        'git://code.qt.io/qt/qt5.git',
        'git@github.com:typetools/checker-framework.git',
        'git@github.com:google/jimfs.git',
    ]
    for url in urls:
      self.assertEqual(pr_helper._sanitize_repo_url(url), url)

  def test_url_with_newline_injection(self):
    """Newline-based env var injection payload is neutralized."""
    url = 'https://github.com/attacker/repo\nGITHUB_API_URL=https://evil.com'
    result = pr_helper._sanitize_repo_url(url)
    self.assertIsNotNone(result)
    self.assertNotIn('\n', result)

  def test_url_with_carriage_return(self):
    """Carriage returns are stripped from URLs."""
    result = pr_helper._sanitize_repo_url(
        'https://github.com/example/repo\r\nEVIL=1')
    self.assertIsNotNone(result)
    self.assertNotIn('\r', result)
    self.assertNotIn('\n', result)

  def test_url_with_null_byte(self):
    """Null bytes are stripped from URLs."""
    result = pr_helper._sanitize_repo_url('https://github.com/example/repo\x00')
    self.assertIsNotNone(result)
    self.assertNotIn('\x00', result)

  def test_none_returns_none(self):
    """None input returns None (preserves missing main_repo check)."""
    self.assertIsNone(pr_helper._sanitize_repo_url(None))

  def test_url_with_git_suffix(self):
    """URLs with .git suffix are preserved."""
    url = 'https://github.com/google/oss-fuzz.git'
    self.assertEqual(pr_helper._sanitize_repo_url(url), url)

  def test_invalid_scheme_rejected(self):
    """ftp://, file://, and bare strings are rejected."""
    self.assertIsNone(pr_helper._sanitize_repo_url('ftp://example.com/repo'))
    self.assertIsNone(pr_helper._sanitize_repo_url('file:///etc/passwd'))
    self.assertIsNone(pr_helper._sanitize_repo_url('not-a-url'))

  def test_ssh_url_with_newline_injection(self):
    """SSH-style git@ URLs have control chars stripped."""
    url = 'git@github.com:google/repo.git\nEVIL=1'
    result = pr_helper._sanitize_repo_url(url)
    self.assertNotIn('\n', result)
    self.assertEqual(result, 'git@github.com:google/repo.gitEVIL=1')


class IsKnownContributorTest(unittest.TestCase):
  """Verify contact-list matching in is_known_contributor."""

  def test_primary_contact_match(self):
    """Email matching primary_contact is recognized."""
    content = {
        'primary_contact': 'user@example.com',
        'vendor_ccs': [],
        'auto_ccs': []
    }
    self.assertTrue(pr_helper.is_known_contributor(content, 'user@example.com'))

  def test_vendor_ccs_match(self):
    """Email in vendor_ccs list is recognized."""
    content = {
        'primary_contact': 'other@example.com',
        'vendor_ccs': ['user@example.com'],
        'auto_ccs': []
    }
    self.assertTrue(pr_helper.is_known_contributor(content, 'user@example.com'))

  def test_auto_ccs_match(self):
    """Email in auto_ccs list is recognized."""
    content = {
        'primary_contact': 'other@example.com',
        'vendor_ccs': [],
        'auto_ccs': ['user@example.com']
    }
    self.assertTrue(pr_helper.is_known_contributor(content, 'user@example.com'))

  def test_no_match(self):
    """Unknown email is not recognized as a contributor."""
    content = {
        'primary_contact': 'other@example.com',
        'vendor_ccs': [],
        'auto_ccs': []
    }
    self.assertFalse(pr_helper.is_known_contributor(content,
                                                    'user@example.com'))


if __name__ == '__main__':
  unittest.main()
