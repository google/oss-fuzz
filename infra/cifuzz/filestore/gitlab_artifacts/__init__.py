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
"""Gitlab artifacts filestore implementation."""
import logging

import json
import os
import shutil
import tempfile

import filestore
import http_utils

# pylint:disable=no-self-use,unused-argument


class GitlabArtifactsFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Gitlab job artifacts.
  Either needs to use a cache.
  Or needs a PRIVATE-TOKEN supplied to access the Gitlab API as it seems
  the only way to know which job id to use to download an artifact
  from another job"""

  def __init__(self, config):
    super().__init__(config)
    # Set of downloaded artifacts
    self.downloaded = set()
    self.artifacts_dir = self.config.platform_conf.artifacts_dir
    self.cache_dir = self.config.platform_conf.cache_dir
    self.download_dir = self.config.platform_conf.download_dir
    self.api_url = self.config.platform_conf.api_url

  def _copy_from_dir(self, src, name, reason):
    dest_dir_artifacts = os.path.join(self.config.project_src_path,
                                      self.artifacts_dir, reason, name)
    logging.info('Uploading %s to artifacts to %s.', reason, dest_dir_artifacts)
    shutil.copytree(src, dest_dir_artifacts)
    # Saves to gitlab cache if any is specified.
    if self.cache_dir:
      dest_dir_cache = os.path.join(self.config.project_src_path,
                                    self.cache_dir, reason, name)
      logging.info('Copying from %s to cache %s.', src, dest_dir_cache)
      shutil.copytree(src, dest_dir_cache)

  def upload_crashes(self, name, directory):
    """Gitlab artifacts implementation of upload_crashes."""
    self._copy_from_dir(directory, name, 'crashes')

  def upload_corpus(self, name, directory, replace=False):
    """Gitlab artifacts implementation of upload_corpus."""
    self._copy_from_dir(directory, name, 'corpus')

  def upload_build(self, name, directory):
    """Gitlab artifacts implementation of upload_build."""
    self._copy_from_dir(directory, name, 'build')

  def upload_coverage(self, name, directory):
    """Gitlab artifacts implementation of upload_coverage."""
    self._copy_from_dir(directory, name, 'coverage')

  def _get_job_id(self, proj_path, reason):
    """Get a specific job id for the latest succesful pipeline
    with the specific job name."""
    # We could avoid PRIVATE-TOKEN and use only JOB-TOKEN
    # by looping over all job ids until we find a relevant artifacts archive
    headers = {'PRIVATE-TOKEN': self.config.platform_conf.private_token}
    jobs_url = self.api_url + proj_path + '/jobs?scope=success'
    with tempfile.NamedTemporaryFile() as tmp_file:
      if not http_utils.get_json_from_url(
          jobs_url, tmp_file.name, headers=headers):
        logging.error('Failed downloading %s.', jobs_url)
        return None
      # jq '.[] | select(.name=="clusterfuzzlite-corpus") | .id'
      with open(tmp_file.name, encoding='ascii') as json_file:
        data = json.load(json_file)
        for job in data:
          # job names are fixed by this
          if job['name'] == 'clusterfuzzlite-' + reason:
            logging.info('Latest job with %s is %d.', reason, job['id'])
            return job['id']
    return None

  def _copy_to_dir(self, dst, name, reason):
    if self.cache_dir:
      # Use the cache if any.
      src_dir_cache = os.path.join(self.config.project_src_path, self.cache_dir,
                                   reason, name)
      if not os.path.exists(src_dir_cache):
        logging.info('Cache %s does not exist.', src_dir_cache)
        return False
      shutil.copytree(src_dir_cache, dst, dirs_exist_ok=True)
      logging.info('Copying %s from cache to %s.', src_dir_cache, dst)
      return True
    # Otherwise, use artifacts with gitlab API.
    if reason not in self.downloaded:
      # This is the first time sich an artifacts is required :
      # it needs to be downloaded.
      proj_path = '/projects/' + self.config.platform_conf.project_ref_encoded
      job_id = self._get_job_id(proj_path, reason)
      if not job_id:
        logging.error('Could not find job id for %s.', reason)
      else:
        headers = {'JOB-TOKEN': self.config.token}
        src_url = self.api_url + proj_path + '/jobs/' + str(
            job_id) + '/artifacts'
        logging.info('Downloading artifacts from %s.', src_url)
        download_dir = os.path.join(self.config.workspace, self.download_dir)
        os.makedirs(download_dir, exist_ok=True)
        http_utils.download_and_unpack_zip(src_url,
                                           download_dir,
                                           headers=headers)
        self.downloaded.add(reason)
    if reason in self.downloaded:
      # There was an artifacts archive downloaded, now just use it.
      src_dir = os.path.join(self.config.workspace, self.download_dir,
                             self.artifacts_dir, reason, name)
      logging.info('Downloading %s to artifacts to %s.', src_dir, dst)
      shutil.copytree(src_dir, dst, dirs_exist_ok=True)
      return True
    return False

  def download_corpus(self, name, dst_directory):
    """Gitlab artifacts implementation of download_corpus."""
    self._copy_to_dir(dst_directory, name, 'corpus')

  def download_build(self, name, dst_directory):
    """Gitlab artifacts implementation of download_build."""
    return self._copy_to_dir(dst_directory, name, 'build')

  def download_coverage(self, name, dst_directory):
    """Gitlab artifacts implementation of download_coverage."""
    return self._copy_to_dir(dst_directory, name, 'coverage')
