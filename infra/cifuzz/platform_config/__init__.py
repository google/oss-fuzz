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
"""Module for getting the configuration CIFuzz needs to run."""
import logging
import os

import environment


class BasePlatformConfig:
  """Base class for PlatformConfig subclasses."""

  @property
  def project_src_path(self):
    """Returns the manually checked out path of the project's source if
    specified or None."""
    path = os.getenv('PROJECT_SRC_PATH')
    if not path:
      logging.debug('No PROJECT_SRC_PATH.')
      return path

    logging.debug('PROJECT_SRC_PATH: %s.', path)
    return path

  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('WORKSPACE')

  # Optional config variables.

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
    return None

  @property
  def base_commit(self):
    """Returns the base commit to diff against (commit fuzzing)."""
    # TODO(metzman) Rename base_commit to git_base_commit.
    return os.getenv('GIT_BASE_COMMIT')

  @property
  def base_ref(self):
    """Returns the base branch to diff against (pr fuzzing)."""
    # TODO(metzman) Rename base_ref to git_base_ref.
    return os.getenv('GIT_BASE_REF')

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
    return None

  @property
  def project_repo_owner(self):
    """Returns the project repo owner (githubism)."""
    return None

  @property
  def project_repo_name(self):
    """Returns the project repo name."""
    return os.environ.get('REPOSITORY')

  @property
  def actor(self):
    """Name of the actor for the CI."""
    return None

  @property
  def token(self):
    """Returns the CI API token."""
    return None

  @property
  def docker_in_docker(self):
    """Returns whether or not CFL is running using Docker in Docker."""
    return environment.get_bool('DOCKER_IN_DOCKER', False)

  @property
  def filestore(self):
    """Returns the filestore used to store persistent data."""
    return os.environ.get('FILESTORE')

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
    return None
