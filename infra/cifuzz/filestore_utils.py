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
import filestore.github_actions


def get_filestore(config):
  """Returns the correct filestore based on the platform in |config|.
  Raises an exception if there is no correct filestore for the platform."""
  # TODO(metzman): Force specifying of filestore.
  if config.platform == config.Platform.EXTERNAL_GITHUB:
    return filestore.github_actions.GithubActionsFilestore(config)
  raise filestore.FilestoreError('Filestore doesn\'t support platform.')
