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
"""Module for getting the configuration CIFuzz needs to run on Github."""
import os

import ci_environment


class CiEnvironment(ci_environment.BaseCiEnvironment):
  """CI environment for GitHub."""

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('GITHUB_WORKSPACE')

  @property
  def git_sha(self):
    """Returns the Git SHA to diff against."""
    return os.getenv('GITHUB_SHA')

  @property
  def actor(self):
    """Name of the actor for the CI."""
    return os.getenv('GITHUB_ACTOR')

  @property
  def token(self):
    """Returns the CI API token."""
    return os.getenv('GITHUB_TOKEN')

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or None. The path returned is relative to |self.workspace| since
    on github the checkout will be relative to there."""
    # On GitHub, they don't know the absolute path, it is relative to
    # |workspace|.
    project_src_path = super().project_src_path
    if project_src_path is None:
      return project_src_path

    return os.path.join(self.workspace, project_src_path)

  @property
  def project_repo_owner_and_name(self):
    """Returns a tuple containing the project repo owner and the name of the
    repo."""
    # On GitHub this includes owner and repo name.
    repository = os.getenv('GITHUB_REPOSITORY')
    # Use os.path.split to split owner from repo.
    return os.path.split(repository)

  @property
  def repo_url(self):
    """Returns the GitHub repo URL."""
    repository = os.getenv('GITHUB_REPOSITORY')
    return f'https://github.com/{repository}.git'
