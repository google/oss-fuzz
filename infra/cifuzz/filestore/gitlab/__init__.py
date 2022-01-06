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
"""Gitlab filestore implementation."""
import logging

import json
import os
import shutil
import tempfile

import filestore
import http_utils

# pylint:disable=no-self-use,unused-argument


class GitlabFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Gitlab.
  Needs a cache to upload and downlaod builds.
  Needs a git repository for corpus and coverage.   
  """

  BUILD_PREFIX = 'build-'
  CRASHES_PREFIX = 'crashes-'

  def __init__(self, config):
    super().__init__(config)
    self.artifacts_dir = self.config.platform_conf.artifacts_dir
    self.cache_dir = self.config.platform_conf.cache_dir
    self.git_filestore = filestore.git.GitFilestore(config, None)

  def upload_crashes(self, name, directory):
    """Gitlab artifacts implementation of upload_crashes."""
    # Upload crashes as job artifacts.
    if os.listdir(directory):
      dest_dir_artifacts = os.path.join(self.config.project_src_path,
                                        self.artifacts_dir,
                                        self.CRASHES_PREFIX + name)
      logging.info('Uploading artifacts to %s.', dest_dir_artifacts)
      shutil.copytree(directory, dest_dir_artifacts)

  def upload_corpus(self, name, directory, replace=False):
    """Gitlab artifacts implementation of upload_corpus."""
    # Use the git filestore.
    self.git_filestore.upload_corpus(name, directory, replace)

  def upload_build(self, name, directory):
    """Gitlab artifacts implementation of upload_build."""
    # Puts build into the cache.
    dest_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                  self.BUILD_PREFIX + name)
    logging.info('Copying from %s to cache %s.', directory, dest_dir_cache)
    shutil.copytree(directory, dest_dir_cache, dirs_exist_ok=True)

  def upload_coverage(self, name, directory):
    """Gitlab artifacts implementation of upload_coverage."""
    # Use the git filestore.
    self.git_filestore.upload_coverage(name, directory)

  def download_corpus(self, name, dst_directory):
    """Gitlab artifacts implementation of download_corpus."""
    # Use the git filestore.
    self.git_filestore.download_corpus(name, dst_directory)

  def download_build(self, name, dst_directory):
    """Gitlab artifacts implementation of download_build."""
    # Gets build from the cache.
    src_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                 self.BUILD_PREFIX + name)
    if not os.path.exists(src_dir_cache):
      logging.info('Cache %s does not exist.', src_dir_cache)
      return False
    shutil.copytree(src_dir_cache, dst_directory, dirs_exist_ok=True)
    logging.info('Copying %s from cache to %s.', src_dir_cache, dst_directory)
    return True

  def download_coverage(self, name, dst_directory):
    """Gitlab artifacts implementation of download_coverage."""
    # Use the git filestore.
    self.git_filestore.download_coverage(name, dst_directory)
