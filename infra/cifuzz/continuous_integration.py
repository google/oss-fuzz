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
"""Implementations for various CI systems."""

import os
import collections
import sys
import logging

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build_specified_commit
import docker
import helper
import repo_manager
import retry
import utils

# pylint: disable=too-few-public-methods

BuildPreparationResult = collections.namedtuple(
    'BuildPreparationResult', ['success', 'image_repo_path', 'repo_manager'])


def fix_git_repo_for_diff(repo_manager_obj):
  """Fixes git repos cloned by the "checkout" action so that diffing works on
  them."""
  command = [
      'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
      'refs/remotes/origin/master'
  ]
  return utils.execute(command, location=repo_manager_obj.repo_dir)


class BaseCi:
  """Class representing common CI functionality."""

  def __init__(self, config):
    self.config = config

  def prepare_for_fuzzer_build(self):
    """Builds the fuzzer builder image and gets the source code we need to
    fuzz."""
    raise NotImplementedError('Children must implement this method.')

  def get_diff_base(self):
    """Returns the base to diff against with git to get the change under
    test."""
    raise NotImplementedError('Children must implement this method.')

  def get_changed_code_under_test(self, repo_manager_obj):
    """Returns the changed files that need to be tested."""
    base = self.get_diff_base()
    fix_git_repo_for_diff(repo_manager_obj)
    logging.info('Diffing against %s.', base)
    return repo_manager_obj.get_git_diff(base)


def get_ci(config):
  """Determines what kind of CI is being used and returns the object
  representing that system."""

  if config.platform == config.Platform.EXTERNAL_GENERIC_CI:
    # Non-OSS-Fuzz projects must bring their own source and their own build
    # integration (which is relative to that source).
    return ExternalGeneric(config)
  if config.platform == config.Platform.EXTERNAL_GITHUB:
    # Non-OSS-Fuzz projects must bring their own source and their own build
    # integration (which is relative to that source).
    return ExternalGithub(config)

  if config.platform == config.Platform.INTERNAL_GENERIC_CI:
    # Builds of OSS-Fuzz projects not hosted on Github must bring their own
    # source since the checkout logic CIFuzz implements is github-specific.
    # TODO(metzman): Consider moving Github-actions builds of OSS-Fuzz projects
    # to this system to reduce implementation complexity.
    return InternalGeneric(config)

  return InternalGithub(config)


def checkout_specified_commit(repo_manager_obj, pr_ref, commit_sha):
  """Checks out the specified commit or pull request using
  |repo_manager_obj|."""
  try:
    if pr_ref:
      repo_manager_obj.checkout_pr(pr_ref)
    else:
      repo_manager_obj.checkout_commit(commit_sha)
  except (RuntimeError, ValueError):
    logging.error(
        'Can not check out requested state %s. '
        'Using current repo state', pr_ref or commit_sha)


class GithubCiMixin:
  """Mixin for Github based CI systems."""

  def get_diff_base(self):
    """Returns the base to diff against with git to get the change under
    test."""
    if self.config.base_ref:
      logging.debug('Diffing against base_ref: %s.', self.config.base_ref)
      return self.config.base_ref
    logging.debug('Diffing against base_commit: %s.', self.config.base_commit)
    return self.config.base_commit

  def get_changed_code_under_test(self, repo_manager_obj):
    """Returns the changed files that need to be tested."""
    if self.config.base_ref:
      repo_manager_obj.fetch_branch(self.config.base_ref)
    return super().get_changed_code_under_test(repo_manager_obj)


class InternalGithub(GithubCiMixin, BaseCi):
  """Class representing CI for an OSS-Fuzz project on Github Actions."""

  def prepare_for_fuzzer_build(self):
    """Builds the fuzzer builder image, checks out the pull request/commit and
    returns the BuildPreparationResult."""
    logging.info('Building OSS-Fuzz project on Github Actions.')
    assert self.config.pr_ref or self.config.commit_sha
    # detect_main_repo builds the image as a side effect.
    inferred_url, image_repo_path = (build_specified_commit.detect_main_repo(
        self.config.oss_fuzz_project_name,
        repo_name=self.config.project_repo_name))

    if not inferred_url or not image_repo_path:
      logging.error('Could not detect repo.')
      return BuildPreparationResult(success=False,
                                    image_repo_path=None,
                                    repo_manager=None)

    git_workspace = os.path.join(self.config.workspace, 'storage')
    os.makedirs(git_workspace, exist_ok=True)

    # Use the same name used in the docker image so we can overwrite it.
    image_repo_name = os.path.basename(image_repo_path)

    # Checkout project's repo in the shared volume.
    manager = repo_manager.clone_repo_and_get_manager(inferred_url,
                                                      git_workspace,
                                                      repo_name=image_repo_name)
    checkout_specified_commit(manager, self.config.pr_ref,
                              self.config.commit_sha)

    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)


class InternalGeneric(BaseCi):
  """Class representing CI for an OSS-Fuzz project on a CI other than Github
  actions."""

  def prepare_for_fuzzer_build(self):
    """Builds the project builder image for an OSS-Fuzz project outside of
    GitHub actions. Returns the repo_manager. Does not checkout source code
    since external projects are expected to bring their own source code to
    CIFuzz."""
    logging.info('Building OSS-Fuzz project.')
    # detect_main_repo builds the image as a side effect.
    _, image_repo_path = (build_specified_commit.detect_main_repo(
        self.config.oss_fuzz_project_name,
        repo_name=self.config.project_repo_name))

    if not image_repo_path:
      logging.error('Could not detect repo.')
      return BuildPreparationResult(success=False,
                                    image_repo_path=None,
                                    repo_manager=None)

    manager = repo_manager.RepoManager(self.config.project_src_path)
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)

  def get_diff_base(self):
    return 'origin...'


_IMAGE_BUILD_TRIES = 3
_IMAGE_BUILD_BACKOFF = 2


@retry.wrap(_IMAGE_BUILD_TRIES, _IMAGE_BUILD_BACKOFF)
def build_external_project_docker_image(project_src, build_integration_path):
  """Builds the project builder image for an external (non-OSS-Fuzz) project.
  Returns True on success."""
  dockerfile_path = os.path.join(build_integration_path, 'Dockerfile')
  command = [
      '-t', docker.EXTERNAL_PROJECT_IMAGE, '-f', dockerfile_path, project_src
  ]
  return helper.docker_build(command)


class ExternalGeneric(BaseCi):
  """CI implementation for generic CI for external (non-OSS-Fuzz) projects."""

  def get_diff_base(self):
    return 'origin...'

  def prepare_for_fuzzer_build(self):
    logging.info('ExternalGeneric: preparing for fuzzer build.')
    manager = repo_manager.RepoManager(self.config.project_src_path)
    build_integration_abs_path = os.path.join(
        manager.repo_dir, self.config.build_integration_path)
    if not build_external_project_docker_image(manager.repo_dir,
                                               build_integration_abs_path):
      logging.error('Failed to build external project: %s.',
                    self.config.oss_fuzz_project_name)
      return BuildPreparationResult(success=False,
                                    image_repo_path=None,
                                    repo_manager=None)

    image_repo_path = os.path.join('/src', self.config.project_repo_name)
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)


class ExternalGithub(GithubCiMixin, BaseCi):
  """Class representing CI for a non-OSS-Fuzz project on Github Actions."""

  def prepare_for_fuzzer_build(self):
    """Builds the project builder image for a non-OSS-Fuzz project on GitHub
    actions. Sets the repo manager. Does not checkout source code since external
    projects are expected to bring their own source code to CIFuzz. Returns True
    on success."""
    logging.info('Building external project.')
    git_workspace = os.path.join(self.config.workspace, 'storage')
    os.makedirs(git_workspace, exist_ok=True)
    # Checkout before building, so we don't need to rely on copying the source
    # into the image.
    # TODO(metzman): Figure out if we want second copy at all.
    manager = repo_manager.clone_repo_and_get_manager(
        self.config.git_url,
        git_workspace,
        repo_name=self.config.project_repo_name)
    checkout_specified_commit(manager, self.config.pr_ref,
                              self.config.commit_sha)

    build_integration_abs_path = os.path.join(
        manager.repo_dir, self.config.build_integration_path)
    if not build_external_project_docker_image(manager.repo_dir,
                                               build_integration_abs_path):
      logging.error('Failed to build external project.')
      return BuildPreparationResult(success=False,
                                    image_repo_path=None,
                                    repo_manager=None)

    image_repo_path = os.path.join('/src', self.config.project_repo_name)
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)
