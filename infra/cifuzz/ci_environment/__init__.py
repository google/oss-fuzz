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


class BaseCiEnvironment:
  """Base class for CiEnvironment subclasses."""

  # TODO(metzman): Alphabetize these.
  @property
  def workspace(self):
    """Returns the workspace."""
    return os.getenv('WORKSPACE')

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

  # Optional config variables.

  @property
  def git_sha(self):
    """Returns the Git SHA to diff against."""
    return os.getenv('GIT_SHA')

  @property
  def project_repo_owner_and_name(self):
    """Returns a tuple containing the project repo owner and None."""
    repository = os.getenv('REPOSITORY')
    # Repo owner is a githubism.
    return None, repository

  @property
  def actor(self):
    """Name of the actor for the CI."""
    return os.getenv('ACTOR')

  @property
  def token(self):
    """Returns the CI API token."""
    return os.getenv('TOKEN')

  @property
  def repo_url(self):
    """Returns the repo URL."""
    return os.getenv('REPOSITORY_URL')
