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

import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import http_utils

mock_get_response = mock.MagicMock(status_code=200, content=b'')


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
