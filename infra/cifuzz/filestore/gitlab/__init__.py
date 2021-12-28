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
"""Empty filestore implementation for platforms that haven't implemented it."""
import logging

import shutil
import os
import json
import tempfile

import environment
import http_utils
import filestore

# pylint:disable=no-self-use,unused-argument


class GitlabFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Gitlab job artifacts. Relies on
  having a PRIVATE-TOKEN supplied to access the Gitlab API as seems
  the only way to download an artifact from another job"""

  def __init__(self, config):
    super().__init__(config)
    self.downloaded = set()
    self.artifacts_dir = environment.get('CFL_ARTIFACTS_DIR', 'artifacts')
    self.download_dir = environment.get('CFL_DOWNLOAD_DIR', 'download')

  def _copy_from_dir(self, src, name, reason):
    dest_dir = os.path.join(self.config.workspace, self.artifacts_dir, reason,
                            name)
    logging.info('Uploading %s to artifacts to %s.', reason, dest_dir)
    shutil.copytree(src, dest_dir)

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
    # Would be neat if we could save CI_JOB_ID somewhere,
    # without needing a token with write-access.
    self._copy_from_dir(directory, name, 'coverage')

  def _get_job_id(self, proj_path, headers, reason):
    """Get a specific job id for the latest succesful pipeline
    with the specific job name."""
    jobs_url = os.getenv('CI_API_V4_URL') + proj_path + '/jobs?scope=success'
    with tempfile.NamedTemporaryFile() as tmp_file:
      if not http_utils.download_url(jobs_url, tmp_file.name, headers=headers):
        logging.error('Failed downloading %s.', jobs_url)
        return None
      # jq '.[] | select(.name=="clusterfuzzlite-corpus") | .id'
      with open(tmp_file.name, encoding='ascii') as json_file:
        data = json.load(json_file)
        for job in data:
          # job names are fixed by this
          if job['name'] == 'clusterfuzzlite-' + reason:
            logging.info('Latest job with %s is %d', reason, job['id'])
            return job['id']
    return None

  def _copy_to_dir(self, dst, name, reason):
    if reason not in self.downloaded:
      branch = os.getenv('CFL_BRANCH')
      if not branch:
        branch = os.getenv('CI_DEFAULT_BRANCH')
      proj_path = '/projects/' + os.getenv(
          'CI_PROJECT_NAMESPACE') + '%2F' + os.getenv('CI_PROJECT_NAME')
      # headers = {'JOB-TOKEN' : os.getenv('CI_JOB_TOKEN')}
      # is not enough to get jobid, we could just loop over them...
      headers = {'PRIVATE-TOKEN': os.getenv('CFL_PRIVATE_TOKEN')}
      jobid = self._get_job_id(proj_path, headers, reason)
      if not jobid:
        logging.error('Could not find job id for %s', reason)
      else:
        srcurl = os.getenv('CI_API_V4_URL') + proj_path + '/jobs/' + str(
            jobid) + '/artifacts'
        logging.info('Downloading artifacts from %s', srcurl)
        download_dir = os.path.join(self.config.workspace, self.download_dir)
        os.makedirs(download_dir, exist_ok=True)
        http_utils.download_and_unpack_zip(srcurl,
                                           download_dir,
                                           headers=headers)
        self.downloaded.add(reason)
    if reason in self.downloaded:
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
