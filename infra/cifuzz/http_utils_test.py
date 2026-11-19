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
"""Tests for http_utils.py"""

import io
import os
import unittest
from unittest import mock
import zipfile

from pyfakefs import fake_filesystem_unittest

import http_utils

mock_get_response = mock.MagicMock(status_code=200, content=b'')


def _create_zip_bytes(member_name, content=b'hello'):
  bio = io.BytesIO()
  with zipfile.ZipFile(bio, 'w') as zf:
    zf.writestr(member_name, content)
  return bio.getvalue()


class DownloadUrlTest(unittest.TestCase):
  """Tests that download_url works."""
  URL = 'https://example.com/file'
  FILE_PATH = '/tmp/file'

  @mock.patch('time.sleep')
  @mock.patch('requests.get', return_value=mock_get_response)
  def test_download_url_no_error(self, mock_urlretrieve, _):
    """Tests that download_url works when there is no error."""
    self.assertTrue(http_utils.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(1, mock_urlretrieve.call_count)

  @mock.patch('time.sleep')
  @mock.patch('logging.error')
  @mock.patch('requests.get',
              return_value=mock.MagicMock(status_code=404, content=b''))
  def test_download_url_http_error(self, mock_get, mock_error, _):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(http_utils.download_url(self.URL, self.FILE_PATH))
    mock_error.assert_called_with(
        'Unable to download from: %s. Code: %d. Content: %s.', self.URL, 404,
        b'')
    self.assertEqual(1, mock_get.call_count)

  @mock.patch('time.sleep')
  @mock.patch('requests.get', side_effect=ConnectionResetError)
  def test_download_url_connection_error(self, mock_get, mock_sleep):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(http_utils.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(4, mock_get.call_count)
    self.assertEqual(3, mock_sleep.call_count)


class IsSafeZipMemberTest(unittest.TestCase):
  """Tests _is_safe_zip_member."""

  def setUp(self):
    self.extract_dir = os.path.abspath('/extract-dir')

  def test_safe_members(self):
    """Tests that normal relative member paths are safe."""
    self.assertTrue(
        http_utils._is_safe_zip_member('file.txt', self.extract_dir))
    self.assertTrue(
        http_utils._is_safe_zip_member('dir/file.txt', self.extract_dir))
    self.assertTrue(
        http_utils._is_safe_zip_member('dir/subdir/file.txt', self.extract_dir))
    self.assertTrue(
        http_utils._is_safe_zip_member('dir/../dir/file.txt', self.extract_dir))

  def test_traversal_members(self):
    """Tests that path traversal member paths are rejected."""
    self.assertFalse(
        http_utils._is_safe_zip_member('../evil.txt', self.extract_dir))
    self.assertFalse(
        http_utils._is_safe_zip_member('../../evil.txt', self.extract_dir))
    self.assertFalse(
        http_utils._is_safe_zip_member('dir/../../evil.txt', self.extract_dir))

  def test_absolute_members(self):
    """Tests that absolute member paths are rejected."""
    self.assertFalse(
        http_utils._is_safe_zip_member('/evil.txt', self.extract_dir))
    self.assertFalse(
        http_utils._is_safe_zip_member('/etc/passwd', self.extract_dir))
    self.assertFalse(
        http_utils._is_safe_zip_member('\\Windows\\System32\\calc.exe',
                                       self.extract_dir))

  def test_drive_members(self):
    """Tests that drive-prefixed paths are rejected."""
    self.assertFalse(
        http_utils._is_safe_zip_member('C:evil.txt', self.extract_dir))
    self.assertFalse(
        http_utils._is_safe_zip_member('C:\\evil.txt', self.extract_dir))

  def test_empty_member(self):
    """Tests that empty member is rejected."""
    self.assertFalse(http_utils._is_safe_zip_member('', self.extract_dir))


class DownloadAndUnpackZipTest(fake_filesystem_unittest.TestCase):
  """Tests download_and_unpack_zip."""

  def setUp(self):
    self.setUpPyfakefs()

  @mock.patch('requests.get', return_value=mock_get_response)
  def test_bad_zip_download(self, _):
    """Tests download_and_unpack_zip returns none when a bad zip is passed."""
    self.fs.create_file('/url_tmp.zip', contents='Test file.')
    self.assertFalse(
        http_utils.download_and_unpack_zip('/not/a/real/url',
                                           '/extract-directory'))

  @mock.patch('http_utils.download_url')
  def test_unpack_zip_traversal_rejected(self, mock_download):
    """Tests that a zip with path traversal member is rejected."""
    def write_zip(url, path, headers=None):  # pylint: disable=unused-argument
      with open(path, 'wb') as f:
        f.write(_create_zip_bytes('../evil.txt', b'malicious'))
      return True

    mock_download.side_effect = write_zip
    extract_dir = '/extract-dir'
    self.fs.create_dir(extract_dir)
    self.assertFalse(
        http_utils.download_and_unpack_zip('http://example.com/test.zip',
                                           extract_dir))
    self.assertFalse(os.path.exists('/evil.txt'))

  @mock.patch('http_utils.download_url')
  def test_unpack_zip_safe(self, mock_download):
    """Tests that a zip with safe member is extracted properly."""
    def write_zip(url, path, headers=None):  # pylint: disable=unused-argument
      with open(path, 'wb') as f:
        f.write(_create_zip_bytes('safe.txt', b'safe content'))
      return True

    mock_download.side_effect = write_zip
    extract_dir = '/extract-dir'
    self.fs.create_dir(extract_dir)
    self.assertTrue(
        http_utils.download_and_unpack_zip('http://example.com/test.zip',
                                           extract_dir))
    expected_file = os.path.join(extract_dir, 'safe.txt')
    self.assertTrue(os.path.exists(expected_file))
    with open(expected_file, 'rb') as f:
      self.assertEqual(f.read(), b'safe content')
