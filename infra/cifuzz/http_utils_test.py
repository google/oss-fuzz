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
import urllib.error

from pyfakefs import fake_filesystem_unittest

import http_utils


class DownloadUrlTest(unittest.TestCase):
  """Tests that download_url works."""
  URL = 'example.com/file'
  FILE_PATH = '/tmp/file'

  @mock.patch('time.sleep')
  @mock.patch('urllib.request.urlretrieve', return_value=True)
  def test_download_url_no_error(self, mocked_urlretrieve, _):
    """Tests that download_url works when there is no error."""
    self.assertTrue(http_utils.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(1, mocked_urlretrieve.call_count)

  @mock.patch('time.sleep')
  @mock.patch('logging.error')
  @mock.patch('urllib.request.urlretrieve',
              side_effect=urllib.error.HTTPError(None, None, None, None, None))
  def test_download_url_http_error(self, mocked_urlretrieve, mocked_error, _):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(http_utils.download_url(self.URL, self.FILE_PATH))
    mocked_error.assert_called_with('Unable to download from: %s.', self.URL)
    self.assertEqual(1, mocked_urlretrieve.call_count)

  @mock.patch('time.sleep')
  @mock.patch('logging.error')
  @mock.patch('urllib.request.urlretrieve', side_effect=ConnectionResetError)
  def test_download_url_connection_error(self, mocked_urlretrieve, mocked_error,
                                         mocked_sleep):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(http_utils.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(3, mocked_urlretrieve.call_count)
    self.assertEqual(3, mocked_sleep.call_count)
    mocked_error.assert_called_with('Failed to download %s, %d times.',
                                    self.URL, 3)


class DownloadAndUnpackZipTest(fake_filesystem_unittest.TestCase):
  """Tests download_and_unpack_zip."""

  def setUp(self):
    self.setUpPyfakefs()

  @mock.patch('urllib.request.urlretrieve', return_value=True)
  def test_bad_zip_download(self, _):
    """Tests download_and_unpack_zip returns none when a bad zip is passed."""
    self.fs.create_file('/url_tmp.zip', contents='Test file.')
    self.assertFalse(
        http_utils.download_and_unpack_zip('/not/a/real/url',
                                           '/extract-directory'))
