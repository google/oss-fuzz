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
"""Implementation of a filestore using Github actions artifacts."""
import os
import logging

from cifuzz import http_utils
from cifuzz import filestore
from cifuzz.third_party.github_actions_toolkit.artifact import artifact_client
from cifuzz.filestore import github_api


class GithubActionsFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Github actions artifacts."""

  def __init__(self, config):
    super().__init__(config)
    authorization = 'token {token}'.format(token=self.config.github_token)
    self.http_headers = {
        'Authorization': authorization,
        'Accept': 'application/vnd.github.v3+json'
    }

  def upload_directory(self, name, directory):  # pylint: disable=no-self-use
    """Uploads |directory| as artifact with |name|."""
    directory = os.path.abspath(directory)

    # Get file paths.
    file_paths = []
    for root, _, curr_file_paths in os.walk(directory):
      for file_path in curr_file_paths:
        file_paths.append(os.path.join(root, file_path))

    logging.debug('file_paths: %s', file_paths)

    # TODO(metzman): Zip so that we can upload directories within directories
    # and save time?

    return artifact_client.upload_artifact(name, file_paths, directory)

  def download_corpus(self, name, dst_directory):  # pylint: disable=unused-argument,no-self-use
    """Downloads the corpus located at |name| to |dst_directory|."""
    logging.debug('listing artifact')
    artifacts = self._list_artifacts()
    corpus_artifact = github_api.find_artifact(name, artifacts)
    logging.debug('Corpus artifact: %s.', corpus_artifact)
    if not corpus_artifact:
      logging.warning('Could not download corpus: %s.', name)
      return False
    url = corpus_artifact['archive_download_url']
    logging.debug('Corpus artifact url: %s.', url)
    return http_utils.download_and_unpack_zip(url,
                                              dst_directory,
                                              headers=self.http_headers)

  def _list_artifacts(self):
    return github_api.list_artifacts(self.config.project_repo_owner,
                                     self.config.project_repo_name,
                                     self.http_headers)

  def download_latest_build(self, name, dst_directory):
    """Downloads latest build with name |name| to |dst_directory|."""
    artifacts = self._list_artifacts()
    build_artifact = github_api.find_artifact(name, artifacts)
    if not build_artifact:
      logging.warning('Could not download build: %s.', name)
      return False

    url = build_artifact['archive_download_url']
    logging.debug('Build artifact url: %s.', url)
    return http_utils.download_and_unpack_zip(url,
                                              dst_directory,
                                              headers=self.http_headers)
