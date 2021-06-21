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

import http_utils
import filestore
from filestore.github_actions import github_api
from third_party.github_actions_toolkit.artifact import artifact_client


class GithubActionsFilestore(filestore.BaseFilestore):
  """Implementation of BaseFilestore using Github actions artifacts. Relies on
  github_actions_toolkit for using the GitHub actions API and the github_api
  module for using GitHub's standard API. We need to use both because the GitHub
  actions API is the only way to upload an artifact but it does not support
  downloading artifacts from other runs. The standard GitHub API does support
  this however."""

  def __init__(self, config):
    super().__init__(config)
    self.github_api_http_headers = github_api.get_http_auth_headers(config)

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
    return self._download_artifact(name, dst_directory)

  def _find_artifact(self, name):
    """Finds an artifact using the GitHub API and returns it."""
    logging.debug('listing artifact')
    artifacts = self._list_artifacts()
    artifact = github_api.find_artifact(name, artifacts)
    logging.debug('Artifact: %s.', artifact)
    return artifact

  def _download_artifact(self, name, dst_directory):
    """Downloads artifact with |name| to |dst_directory|."""
    artifact = self._find_artifact(name)
    if not artifact:
      logging.warning('Could not download artifact: %s.', name)
      return artifact
    download_url = artifact['archive_download_url']
    return http_utils.download_and_unpack_zip(
        download_url, dst_directory, headers=self.github_api_http_headers)

  def _list_artifacts(self):
    """Returns a list of artifacts."""
    return github_api.list_artifacts(self.config.project_repo_owner,
                                     self.config.project_repo_name,
                                     self.github_api_http_headers)

  def download_latest_build(self, name, dst_directory):
    """Downloads latest build with name |name| to |dst_directory|."""
    return self._download_artifact(name, dst_directory)
