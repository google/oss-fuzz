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
"""Utility module for HTTP."""
import logging
import os
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


def download_and_unpack_zip(url, extract_directory, headers=None):
  """Downloads and unpacks a zip file from an HTTP URL.

  Args:
    url: A url to the zip file to be downloaded and unpacked.
    extract_directory: The path where the zip file should be extracted to.
    headers: (Optional) HTTP headers to send with the download request.

  Returns:
    True on success.
  """
  if headers is None:
    headers = {}

  if not os.path.exists(extract_directory):
    logging.error('Extract directory: %s does not exist.', extract_directory)
    return False

  # Gives the temporary zip file a unique identifier in the case that
  # that download_and_unpack_zip is done in parallel.
  with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_file:
    if not download_url(url, tmp_file.name):
      return False

    try:
      with zipfile.ZipFile(tmp_file.name, 'r') as zip_file:
        zip_file.extractall(extract_directory)
    except zipfile.BadZipFile:
      logging.error('Error unpacking zip from %s. Bad Zipfile.', url)
      return False

  return True


def download_url(url, filename, num_attempts=3, headers=None):
  """Downloads the file located at |url|, using HTTP to |filename|.

  Args:
    url: A url to a file to download.
    filename: The path the file should be downloaded to.
    num_retries: The number of times to retry the download on
       ConnectionResetError.
    headers: (Optional) HTTP headers to send with the download request.

  Returns:
    True on success.
  """
  sleep_time = 1
  if headers is None:
    headers = {}

  # Don't use retry wrapper since we don't waont this to raise any exceptions.
  for _ in range(num_attempts):
    # TODO(jonathanmetzman): This is ugly. Switch this module to Python
    # requests. I waited to do this because error handling won't be the same and
    # rewriting tests isn't something I want to spend time on right now.
    try:
      urllib.request.urlretrieve(url, filename)
      return True
    except urllib.error.HTTPError:
      # In these cases, retrying probably wont work since the error probably
      # means there is nothing at the URL to download.
      logging.error('Unable to download from: %s.', url)
      return False
    except ConnectionResetError:
      # These errors are more likely to be transient. Retry.
      pass
    time.sleep(sleep_time)

  logging.error('Failed to download %s, %d times.', url, num_attempts)

  return False
