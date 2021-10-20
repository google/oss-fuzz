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
"""Filestore implementation using gsutil."""
import posixpath
import threading

from clusterfuzz._internal.google_cloud_utils import gsutil

import filestore

# Thread-local global variables.
_local = threading.local()  # pylint: disable=too-few-public-methods

def _create_runner():
  _local.runner = gsutil.GSUtilRunner()

def _runner():
  if getattr(_local, 'runner', None) is None:
    _create_runner()
  return _local.runner


class GSUtilFilestore(filestore.BaseFilestore):
  """Filestore implementation using gsutil."""
  BUILD_DIR = 'build'
  CRASHES_DIR = 'crashes'
  CORPUS_DIR = 'corpus'
  COVERAGE_DIR = 'coverage'

  def __init__(self, config):
    super().__init__(config)
    self._runner = _runner()
    self._cloud_bucket = self.config.cloud_bucket

  def get_gsutil_url(self, name, prefix_dir):
    """Returns the gsutil URL for |name| and |prefix_dir|."""
    if not prefix_dir:
      return posixpath.join(self._cloud_bucket, name)
    return posixpath.join(self._cloud_bucket, prefix_dir, name)

  def _upload_directory(self, name, directory, prefix, delete=False):
    gsutil_url = self.get_gsutil_url(name, prefix)
    return self._runner.rsync(directory, gsutil_url, delete=delete)

  def _download_directory(self, name, dst_directory, prefix):
    gsutil_url = self.get_gsutil_url(name, prefix)
    return self._runner.rsync(gsutil_url, dst_directory)

  def upload_crashes(self, name, directory):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(name, directory, self.CRASHES_DIR)

  def upload_corpus(self, name, directory, replace=False):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(
        name, directory, self.CORPUS_DIR, delete=replace)

  def upload_build(self, name, directory):
    """Uploads the build located at |directory| to |name|."""
    return self._upload_directory(name, directory, self.BUILD_DIR)

  def upload_coverage(self, name, directory):
    """Uploads the coverage report at |directory| to |name|."""
    return self._upload_directory(name, directory, self.COVERAGE_DIR)

  def download_corpus(self, name, dst_directory):
    """Downloads the corpus located at |name| to |dst_directory|."""
    return self._download_directory(name, dst_directory, self.CORPUS_DIR)

  def download_build(self, name, dst_directory):
    """Downloads the build with |name| to |dst_directory|."""
    return self._download_directory(name, dst_directory, self.BUILD_DIR)

  def download_coverage(self, name, dst_directory):
    """Downloads the latest project coverage report."""
    return self._download_directory(name, dst_directory, self.COVERAGE_DIR)
