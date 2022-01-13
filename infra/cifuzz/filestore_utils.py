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
"""External filestore interface. Cannot be depended on by filestore code."""
import filestore
import filestore.git
import filestore.github_actions
import filestore.gsutil
import filestore.no_filestore
import filestore.gitlab

FILESTORE_MAPPING = {
    'gsutil': filestore.gsutil.GSUtilFilestore,
    'github-actions': filestore.github_actions.GithubActionsFilestore,
    'git': filestore.git.GitFilestore,
    'no_filestore': filestore.no_filestore.NoFilestore,
    'gitlab': filestore.gitlab.GitlabFilestore,
}


def get_filestore(config):
  """Returns the correct filestore object based on the platform in |config|.
  Raises an exception if there is no correct filestore for the platform."""
  if config.platform == config.Platform.EXTERNAL_GITHUB:
    ci_filestore = filestore.github_actions.GithubActionsFilestore(config)
    if not config.git_store_repo:
      return ci_filestore

    return filestore.git.GitFilestore(config, ci_filestore)

  filestore_cls = FILESTORE_MAPPING.get(config.filestore)
  if filestore_cls is None:
    raise filestore.FilestoreError('Filestore doesn\'t exist.')
  return filestore_cls(config)
