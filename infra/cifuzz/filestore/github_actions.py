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
import sys

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import http_utils
import filestore
from github_actions_toolkit.artifact import artifact_client
from filestore import github_api


class GithubActionsFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Github actions artifacts."""

  def __init__(self, config):
    super().__init__(config)
    authorization = 'token {token}'.format(token=self.config.github_token)
    self.http_headers = {
        'Authorization': authorization,
        'Accept': 'application/vnd.github.v3+json'
    }

  def upload_corpus(self, name, directory):  # pylint: disable=no-self-use
    """Uploads the corpus located at |directory| to |name|."""
    directory = os.path.abspath(directory)

    # Get file paths.
    file_paths = []
    for root, _, curr_file_paths in os.walk(directory):
      for file_path in curr_file_paths:
        file_paths.append(os.path.join(root, file_path))

    # !!! Zip it to make uploads faster (need to deal with double zip problem).

    return artifact_client.upload_artifact(name, file_paths, directory)

  def download_corpus(self, name, dst_directory):  # pylint: disable=unused-argument,no-self-use
    """Downloads the corpus located at |name| to |dst_directory|."""
    logging.debug('listing artifact')
    artifacts = github_api.list_artifacts(self.config.project_repo_owner,
                                          self.config.project_repo_name,
                                          self.http_headers)
    if not artifacts:
      logging.error('Failed to get artifacts.')
      return dst_directory
    corpus_artifact = github_api.find_corpus_artifact(name, artifacts)
    logging.debug('corpus artifact: %s', corpus_artifact)
    url = corpus_artifact['archive_download_url']
    logging.debug('corpus artifact url: %s', url)
    # import time
    # import base64
    # t = self.config.github_token.replace('a', '-').encode()
    # for _ in range(60 * 60):
    #   logging.debug('self.config.github_token %s',
    #                 base64.b64encode(t))
    #   time.sleep(1)

    return http_utils.download_and_unpack_zip(url,
                                              dst_directory,
                                              headers=self.http_headers)
