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
"""Public interface for artifact. Based on artifact-client.ts"""
import logging

from github_actions_toolkit.artifact import utils
from github_actions_toolkit.artifact import upload_http_client
from github_actions_toolkit.artifact import upload_specification


def upload_artifact(name, files, root_directory, options=None):
  """Uploads an artifact based on uploadArtifact."""
  utils.check_artifact_name(name)
  upload_spec = upload_specification.get_upload_specification(
      name, root_directory, files)

  upload_response = {
      'artifactName': name,
      'artifactItems': [],
      'size': 0,
      'failedItems': []
  }
  if len(upload_spec) == 0:
    raise Exception('No files to upload')

  response = upload_http_client.create_artifact_in_file_container(name, options)
  file_container_resource_url = response.get('fileContainerResourceUrl')
  if not file_container_resource_url:
    logging.debug('create_artifact_in_file_container response: %s.', response)
    # !!! dbg code
    file_container_resource_url = (
        'https://httpbin.org/anything/fileContainerResourceUrl/')
    raise Exception('GitHub artifacts API didn\'t provide upload URL')

  logging.debug('Upload resource URL: %s', file_container_resource_url)
  upload_result = upload_http_client.upload_artifact_to_file_container(
      file_container_resource_url, upload_spec, options)
  # Update artifact size when done.
  # Uncompressed size used in UI when downloading a zip of the artifact.
  upload_http_client.patch_artifact_size(upload_result['totalSize'], name)
  logging.info(
      'Uploaded artifact: %s, size is: %s bytes, '
      '%d items failed to upload.', name, upload_result['uploadSize'],
      len(upload_result['failedItems']))
  upload_response['artifactItems'] = [
      spec.absolute_file_path for spec in upload_spec
  ]
  upload_response['size'] = upload_result['uploadSize']
  upload_response['failedItems'] = upload_result['failedItems']
  return upload_response
