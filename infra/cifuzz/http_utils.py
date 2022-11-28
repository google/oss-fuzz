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
import json
import logging
import os
import sys
import tempfile
import zipfile

import requests

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import retry

_DOWNLOAD_URL_RETRIES = 3
_DOWNLOAD_URL_BACKOFF = 1
_HTTP_REQUEST_TIMEOUT = 10


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
    if not download_url(url, tmp_file.name, headers=headers):
      return False

    try:
      with zipfile.ZipFile(tmp_file.name, 'r') as zip_file:
        zip_file.extractall(extract_directory)
    except zipfile.BadZipFile:
      logging.error('Error unpacking zip from %s. Bad Zipfile.', url)
      return False

  return True


def download_url(*args, **kwargs):
  """Wrapper around _download_url that returns False if _download_url
  exceptions."""
  try:
    return _download_url(*args, **kwargs)
  except Exception:  # pylint: disable=broad-except
    return False


def get_json_from_url(url):
  """Gets a json object from a specified HTTP URL.

  Args:
    url: The url of the json to be downloaded.

  Returns:
    A dictionary deserialized from JSON or None on failure.
  """
  try:
    return requests.get(url, timeout=_HTTP_REQUEST_TIMEOUT).json()
  except (ValueError, TypeError, json.JSONDecodeError,
          requests.exceptions.ReadTimeout) as err:
    logging.error('Loading json from url %s failed with: %s.', url, str(err))
    return None


@retry.wrap(_DOWNLOAD_URL_RETRIES, _DOWNLOAD_URL_BACKOFF)
def _download_url(url, filename, headers=None):
  """Downloads the file located at |url|, using HTTP to |filename|.

  Args:
    url: A url to a file to download.
    filename: The path the file should be downloaded to.
    headers: (Optional) HTTP headers to send with the download request.

  Returns:
    True on success.
  """
  if headers is None:
    headers = {}

  response = requests.get(url, headers=headers)

  if response.status_code != 200:
    logging.error('Unable to download from: %s. Code: %d. Content: %s.', url,
                  response.status_code, response.content)
    return False

  with open(filename, 'wb') as file_handle:
    file_handle.write(response.content)

  return True
