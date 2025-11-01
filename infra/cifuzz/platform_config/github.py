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
import json
import logging
import os

import platform_config


def _get_github_event_path():
  return os.getenv('GITHUB_EVENT_PATH')


def _get_event_data():
  """Returns the GitHub event data."""
  github_event_path = _get_github_event_path()
  with open(github_event_path, encoding='utf-8') as file_handle:
    return json.load(file_handle)


class PlatformConfig(platform_config.BasePlatformConfig):
  """CI environment for GitHub."""

  def __init__(self):
    self._event_data = _get_event_data()
    self._event = os.getenv('GITHUB_EVENT_NAME')

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('GITHUB_WORKSPACE')

  @property
  def git_sha(self):
    """Returns the Git SHA to checkout and fuzz. This is used only by GitHub
    projects when commit fuzzing. It is not used when PR fuzzing. It is
    definitely needed by OSS-Fuzz on GitHub since they have no copy of the repo
    on the host and the repo on the builder image is a clone from main/master.
    Right now it is needed by external on GitHub because we need to clone a new
    repo because the copy they give us doesn't work for diffing.

    TODO(metzman): Try to eliminate the need for this by 1. Making the clone
    from external github projects usable. 2. Forcing OSS-Fuzz on Github to clone
    before starting CIFuzz."""
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
    project_src_path = super().project_src_path
    if project_src_path is None:
      # Not set for internal GitHub users.
      return project_src_path
    # On GitHub (external users), this path is relative to |workspace|.
    return os.path.join(self.workspace, project_src_path)

  @property
  def _project_repo_owner_and_name(self):
    """Returns a tuple containing the project repo owner and the name of the
    repo."""
    # On GitHub this includes owner and repo name.
    repository = os.getenv('GITHUB_REPOSITORY')
    # Use os.path.split to split owner from repo.
    return os.path.split(repository)

  @property
  def project_repo_owner(self):
    """Returns the project repo owner (githubism)."""
    return self._project_repo_owner_and_name[0]

  @property
  def project_repo_name(self):
    """Returns the project repo name."""
    return self._project_repo_owner_and_name[1]

  @property
  def git_url(self):
    """Returns the repo URL. This is only used by GitHub users. Right now it is
    needed by external on GitHub because we need to clone a new repo because the
    copy they give us doesn't work for diffing. It isn't used by OSS-Fuzz on
    github users since the Git URL is determined using repo detection.

    TODO(metzman): Try to eliminate the need for this by making the clone
    from external github projects usable.
    TODO(metzman): As an easier goal, maybe make OSS-Fuzz GitHub use this too
    for: 1. Consistency 2. Maybe it will allow use on forks."""
    repository = os.getenv('GITHUB_REPOSITORY')
    github_server_url = os.getenv('GITHUB_SERVER_URL', 'https://github.com')
    # TODO(metzman): Probably need to change this to github.server_url.
    return os.path.join(github_server_url, repository)

  @property
  def base_commit(self):
    """Returns the base commit to diff against (commit fuzzing)."""
    base_commit = None
    if self._event == 'push':
      base_commit = self._event_data['before']
    logging.debug('base_commit: %s', base_commit)
    return base_commit

  @property
  def pr_ref(self):
    """Returns the pull request to checkout and fuzz. This is used only by
    GitHub projects when PR fuzzing. It is not used when commit fuzzing. It is
    definitely needed by OSS-Fuzz on GitHub since they have no copy of the repo
    on the host and the repo on the builder image is a clone from main/master.
    Right now it is needed by external on GitHub because we need to clone a new
    repo because the copy they give us doesn't work for diffing.

    TODO(metzman): Try to eliminate the need for this by 1. Making the clone
    from external github projects usable. 2. Forcing OSS-Fuzz on Github to clone
    before starting CIFuzz."""
    if self._event == 'pull_request':
      pr_ref = f'refs/pull/{self._event_data["pull_request"]["number"]}/merge'
      logging.debug('pr_ref: %s', pr_ref)
      return pr_ref
    return None

  @property
  def base_ref(self):
    """Returns the base branch to diff against (pr fuzzing)."""
    return os.getenv('GITHUB_BASE_REF')
