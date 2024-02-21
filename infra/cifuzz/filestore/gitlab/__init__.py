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
"""GitLab filestore implementation."""
import logging

import json
import os
import shutil
import tempfile

import filestore
import http_utils

# pylint: disable=no-self-use,unused-argument


class GitlabFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using GitLab.
  Needs a cache to upload and download builds.
  Needs a git repository for corpus and coverage.
  """

  BUILD_PREFIX = 'build-'
  CORPUS_PREFIX = 'corpus-'
  COVERAGE_PREFIX = 'coverage-'
  CRASHES_PREFIX = 'crashes-'

  def __init__(self, config):
    super().__init__(config)
    self.artifacts_dir = self.config.platform_conf.artifacts_dir
    self.cache_dir = self.config.platform_conf.cache_dir
    if self.config.git_store_repo:
      self.git_filestore = filestore.git.GitFilestore(config, None)
    else:
      self.git_filestore = None

  def upload_crashes(self, name, directory):
    """GitLab artifacts implementation of upload_crashes."""
    # Upload crashes as job artifacts.
    if os.listdir(directory):
      dest_dir_artifacts = os.path.join(self.config.project_src_path,
                                        self.artifacts_dir,
                                        self.CRASHES_PREFIX + name)
      logging.info('Uploading artifacts to %s.', dest_dir_artifacts)
      shutil.copytree(directory, dest_dir_artifacts)

  def upload_corpus(self, name, directory, replace=False):
    """GitLab artifacts implementation of upload_corpus."""
    # Use the git filestore if any.
    if self.git_filestore:
      self.git_filestore.upload_corpus(name, directory, replace)
      return
    # Fall back to cache.
    dest_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                  self.CORPUS_PREFIX + name)
    logging.info('Copying from %s to cache %s.', directory, dest_dir_cache)
    # Remove previous corpus from cache if any.
    shutil.rmtree(dest_dir_cache, ignore_errors=True)
    shutil.copytree(directory, dest_dir_cache, dirs_exist_ok=True)

  def upload_build(self, name, directory):
    """GitLab artifacts implementation of upload_build."""
    # Puts build into the cache.
    dest_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                  self.BUILD_PREFIX + name)
    logging.info('Copying from %s to cache %s.', directory, dest_dir_cache)
    shutil.copytree(directory, dest_dir_cache, dirs_exist_ok=True)

  def upload_coverage(self, name, directory):
    """GitLab artifacts implementation of upload_coverage."""
    # Use the git filestore.
    if self.git_filestore:
      self.git_filestore.upload_coverage(name, directory)
      return
    # Fall back to cache.
    dest_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                  self.COVERAGE_PREFIX + name)
    logging.info('Copying from %s to cache %s.', directory, dest_dir_cache)
    shutil.copytree(directory, dest_dir_cache, dirs_exist_ok=True)
    # And also updates coverage reports as artifacts
    # as it should not be too big.
    dest_dir_artifacts = os.path.join(self.config.project_src_path,
                                      self.artifacts_dir,
                                      self.COVERAGE_PREFIX + name)
    logging.info('Uploading artifacts to %s.', dest_dir_artifacts)
    shutil.copytree(directory, dest_dir_artifacts)

  def _copy_from_cache(self, src_dir_cache, dst_directory):
    if not os.path.exists(src_dir_cache):
      logging.info('Cache %s does not exist.', src_dir_cache)
      return False
    logging.info('Copying %s from cache to %s.', src_dir_cache, dst_directory)
    shutil.copytree(src_dir_cache, dst_directory, dirs_exist_ok=True)
    return True

  def download_corpus(self, name, dst_directory):
    """GitLab artifacts implementation of download_corpus."""
    # Use the git filestore if any.
    if self.git_filestore:
      self.git_filestore.download_corpus(name, dst_directory)
      return
    # Fall back to cache.
    src_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                 self.CORPUS_PREFIX + name)
    self._copy_from_cache(src_dir_cache, dst_directory)

  def download_build(self, name, dst_directory):
    """GitLab artifacts implementation of download_build."""
    # Gets build from the cache.
    src_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                 self.BUILD_PREFIX + name)
    return self._copy_from_cache(src_dir_cache, dst_directory)

  def download_coverage(self, name, dst_directory):
    """GitLab artifacts implementation of download_coverage."""
    # Use the git filestore if any.
    if self.git_filestore:
      return self.git_filestore.download_coverage(name, dst_directory)
    # Fall back to cache.
    src_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                 self.COVERAGE_PREFIX + name)
    return self._copy_from_cache(src_dir_cache, dst_directory)
