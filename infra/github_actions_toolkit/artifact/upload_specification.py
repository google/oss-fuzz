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
"""Module for upload specifications. Based on upload-specification.ts."""
import logging
import os

from github_actions_toolkit.artifact import utils


class UploadSpecification:  # pylint: disable=too-few-public-methods
  """Spec for uploads."""

  def __init__(self, abs_file_path, upload_file_path):
    self.absolute_file_path = abs_file_path
    self.upload_file_path = upload_file_path


def get_upload_specification(artifact_name, root_directory, artifact_files):
  """Returns specifications that describe how files that are part of the
  artifact should be uploaded."""
  specifications = []

  if not root_directory.endswith('/'):
    root_directory += '/'

  for artifact_file in artifact_files:
    if not os.path.exists(artifact_file):
      raise Exception('File does not exist.', artifact_file)

    if os.path.isdir(artifact_file):
      logging.debug('Not uploading diectory: %s.', artifact_file)
      continue

    artifact_file = os.path.normpath(artifact_file)
    if not artifact_file.startswith(root_directory):
      raise Exception('Root directory is not a parent of artifact.',
                      root_directory, artifact_file)
    upload_path = artifact_file.replace(root_directory, '')
    utils.check_artifact_file_path(upload_path)
    upload_file_path = os.path.join(artifact_name, upload_path)
    specification = UploadSpecification(artifact_file, upload_file_path)
    specifications.append(specification)

  return specifications
