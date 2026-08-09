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
"""Filestore implementation using a filesystem directory."""
import logging
import os
import shutil
import subprocess
import sys

from distutils import dir_util

# pylint: disable=wrong-import-position,import-error
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                 os.pardir, os.pardir))
import filestore


def recursive_list_dir(directory):
  """Returns list of all files in |directory|, including those in
  subdirectories."""
  files = []
  for root, _, filenames in os.walk(directory):
    for filename in filenames:
      files.append(os.path.join(root, filename))
  return files


class FilesystemFilestore(filestore.BaseFilestore):
  """Filesystem implementation using a filesystem directory."""
  BUILD_DIR = 'build'
  CRASHES_DIR = 'crashes'
  CORPUS_DIR = 'corpus'
  COVERAGE_DIR = 'coverage'

  def __init__(self, config):
    super().__init__(config)
    self._filestore_root_dir = self.config.platform_conf.filestore_root_dir

  def _get_filestore_path(self, name, prefix_dir):
    """Returns the filesystem path in the filestore for |name| and
    |prefix_dir|."""
    return os.path.join(self._filestore_root_dir, prefix_dir, name)

  def _upload_directory(self, name, directory, prefix, delete=False):
    filestore_path = self._get_filestore_path(name, prefix)
    if os.path.exists(filestore_path):
      initial_files = set(recursive_list_dir(filestore_path))
    else:
      initial_files = set()

    # Make directory and any parents.
    os.makedirs(filestore_path, exist_ok=True)
    copied_files = set(dir_util.copy_tree(directory, filestore_path))
    if not delete:
      return True

    files_to_delete = initial_files - copied_files
    for file_path in files_to_delete:
      os.remove(file_path)
    return True

  def _download_directory(self, name, dst_directory, prefix):
    filestore_path = self._get_filestore_path(name, prefix)
    return dir_util.copy_tree(filestore_path, dst_directory)

  def upload_crashes(self, name, directory):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(name, directory, self.CRASHES_DIR)

  def upload_corpus(self, name, directory, replace=False):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(name,
                                  directory,
                                  self.CORPUS_DIR,
                                  delete=replace)

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
