#!/usr/bin/env python3
#
# Copyright 2023 Google LLC
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
"""Utilities for fuzzbench runs on Google Cloud Build."""

import ast
import collections
import functools
import google.auth
from google.cloud import storage as gcs
import hashlib
import logging
import os
import re
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import retry

GS_PREFIX = 'gs:/'
_local = threading.local()
# The number of retries to perform some GCS operation.
DEFAULT_FAIL_RETRIES = 8
# The time to wait between retries while performing GCS operation.
DEFAULT_FAIL_WAIT = 2


def get_latest_libfuzzer_build_url(project_name):
  """Get the latest LibFuzzer build url."""
  bucket_path = f'gs://clusterfuzz-builds/{project_name}/{project_name}-address-([0-9]+).zip'
  return _get_latest_revision(bucket_path)


def _get_latest_revision(bucket_path):
  """Get the latest revision."""
  urls_list = _get_build_urls_list(bucket_path)
  if not urls_list:
    logging.error('Error getting list of build urls from %s.' % bucket_path)
    return None

  if len(urls_list) == 0:
    logging.error(
        'Attempted to get latest revision, but no build urls were found.')
    return None

  revision_pattern = '.*?' + os.path.basename(bucket_path)
  for build_url in urls_list:
    match = re.match(revision_pattern, build_url)
    if not match:
      continue
    return build_url

  return None


def _get_build_urls_list(bucket_path, reverse=True):
  """Returns a sorted list of build urls from a bucket path."""
  if not bucket_path:
    return []

  base_url = os.path.dirname(bucket_path)
  build_urls = []
  # Get url list by reading the GCS bucket.
  for path in _list_gcs_blobs(base_url):
    build_urls.append(path)

  return _sort_build_urls_by_revision(build_urls, bucket_path, reverse)


@retry.wrap(retries=DEFAULT_FAIL_RETRIES, delay=DEFAULT_FAIL_WAIT)
def _list_gcs_blobs(cloud_storage_path):
  """Return blob names under the given google cloud storage path."""
  for blob_name in GcsProvider().list_blobs_names(cloud_storage_path):
    yield blob_name


def _sort_build_urls_by_revision(build_urls, bucket_path, reverse):
  """Return a sorted list of build url by revision."""
  base_url = os.path.dirname(bucket_path)
  file_pattern = os.path.basename(bucket_path)
  filename_by_revision_dict = {}

  _, base_path = _get_bucket_name_and_path(base_url)
  base_path_with_seperator = base_path + '/' if base_path else ''

  for build_url in build_urls:
    match_pattern = f'{base_path_with_seperator}({file_pattern})'
    match = re.match(match_pattern, build_url)
    if match:
      filename = match.group(1)
      revision = match.group(2)

      # Ensure that there are no duplicate revisions.
      if revision in filename_by_revision_dict:
        logging.error(f'Found duplicate revision {revision} when processing'
                       'bucket.')

      filename_by_revision_dict[revision] = filename

  try:
    sorted_revisions = sorted(
        filename_by_revision_dict,
        reverse=reverse,
        key=lambda x: list(map(int, x.split('.'))))
  except:
    logging.warning(
        'Revision pattern is not an integer, falling back to string sort.')
    sorted_revisions = sorted(filename_by_revision_dict, reverse=reverse)

  sorted_build_urls = []
  for revision in sorted_revisions:
    filename = filename_by_revision_dict[revision]
    sorted_build_urls.append('%s/%s' % (base_url, filename))

  return sorted_build_urls


def _strip_from_left(string, prefix):
  """Strip a prefix from start from string."""
  if not string.startswith(prefix):
    return string
  return string[len(prefix):]


def _get_bucket_name_and_path(cloud_storage_file_path):
  """Return bucket name and path given a full cloud storage path."""
  filtered_path = _strip_from_left(cloud_storage_file_path, GS_PREFIX)
  _, bucket_name_and_path = filtered_path.split('/', 1)

  if '/' in bucket_name_and_path:
    bucket_name, path = bucket_name_and_path.split('/', 1)
  else:
    bucket_name = bucket_name_and_path
    path = ''

  return bucket_name, path


def memoize_wrap(engine):
  """Decorator for caching the result of method calls. Arguments must
    be hashable. None is not cached because we don't tell the difference
    between having None and not having a key."""

  def decorator(func):
    """Decorator function."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      """Wrapper function."""
      force_update = kwargs.pop('__memoize_force__', False)

      key = engine.get_key(func, args, kwargs)
      result = engine.get(key)

      if result is not None and not force_update:
        return result

      result = func(*args, **kwargs)
      engine.put(key, result)
      return result

    return wrapper

  return decorator


class FifoInMemory():
  """In-memory caching engine."""

  def __init__(self, capacity):
    self.capacity = capacity
    self.lock = threading.Lock()
    self._cache = None


  @property
  def cache(self):
    """Get the cache backing. None may be returned."""
    if self._cache is None:
      self._cache = collections.OrderedDict()

    return self._cache


  def put(self, key, value):
    """Put (key, value) into cache."""
    if self.cache is None:
      return

    # Lock to avoid race condition in popitem.
    self.lock.acquire()

    if len(self.cache) >= self.capacity:
      self.cache.popitem(last=False)

    self.cache[key] = value

    self.lock.release()


  def get(self, key):
    """Get the value from cache."""
    if self.cache is None:
      return None

    return self.cache.get(key)


  def get_key(self, func, args, kwargs):
    """Get a key name based on function, arguments and keyword arguments."""
    return self.default_key(func, args, kwargs)


  def default_key(self, func, args, kwargs):
    """Get a key name based on function, arguments and keyword arguments."""
    # Use unicode instead of str where possible. This makes it less likely to
    # have false misses.
    args = tuple(arg if not isinstance(arg, str) else str(arg) for arg in args)

    kwargs = {
        key: value if not isinstance(value, str) else str(value)
        for key, value in kwargs.items()
    }

    return 'memoize:%s' % [func.__name__, args, sorted(kwargs.items())]


class GcsProvider():
  """GCS storage provider."""
  # (me) Should I use this memoize.wrap? - Yes

  @retry.wrap(retries=DEFAULT_FAIL_RETRIES, delay=DEFAULT_FAIL_WAIT)
  @memoize_wrap(FifoInMemory(1))
  def _get_default_credentials(scopes=None):
    """Get default Google Cloud credentials."""
    return google.auth.default(scopes=scopes)


  def _create_storage_client_new(self):
    """Create a storage client."""
    creds, project = self._get_default_credentials()
    return gcs.Client(project=project, credentials=creds)


  def _storage_client(self):
    """Get the storage client, creating it if it does not exist."""
    if not hasattr(_local, 'client'):
      _local.client = self._create_storage_client_new()
    return _local.client


  def list_blobs_names(self, remote_path):
    """List the blobs names under the remote path."""
    bucket_name, path = _get_bucket_name_and_path(remote_path)

    if path and not path.endswith('/'):
      path += '/'

    client = self._storage_client()
    bucket = client.bucket(bucket_name)

    delimiter = None
    fields = None
    iterations = 0
    next_page_token = None

    while True:
      iterations += 1
      iterator = bucket.list_blobs(
          prefix=path, delimiter=delimiter, fields=fields)
      for blob in iterator:
        yield blob.name

      next_page_token = iterator.next_page_token
      if next_page_token is None:
        break
      if iterations and iterations % 50 == 0:
        logging.error('Might be infinite looping.')
