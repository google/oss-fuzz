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
import workspace_utils

# pylint: disable=too-few-public-methods

BuildPreparationResult = collections.namedtuple(
    'BuildPreparationResult', ['success', 'image_repo_path', 'repo_manager'])

_IMAGE_BUILD_TRIES = 3
_IMAGE_BUILD_BACKOFF = 2


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
    self.workspace = workspace_utils.Workspace(config)
    self._repo_dir = None

  @property
  def repo_dir(self):
    """Returns the source repo path, if it has been checked out. None is
    returned otherwise."""
    raise NotImplementedError('Child class must implement method.')

  def prepare_for_fuzzer_build(self):
    """Builds the fuzzer builder image and gets the source code we need to
    fuzz."""
    raise NotImplementedError('Child class must implement method.')

  def get_diff_base(self):
    """Returns the base to diff against with git to get the change under
    test."""
    if self.config.base_ref:
      logging.debug('Diffing against base_ref: %s.', self.config.base_ref)
      return self.config.base_ref
    if self.config.base_commit:
      logging.debug('Diffing against base_commit: %s.', self.config.base_commit)
      return self.config.base_commit
    # TODO(metzman): Do we want this at all? What purpose does it serve? I guess
    # it is a decent fallback when there is no base_commit or base_ref.
    logging.debug('Diffing against origin.')
    return 'origin'

  def get_changed_code_under_test(self, repo_manager_obj):
    """Returns the changed files that need to be tested."""
    if self.config.base_ref:
      repo_manager_obj.fetch_branch(self.config.base_ref)
    fix_git_repo_for_diff(repo_manager_obj)
    base = self.get_diff_base()
    logging.info('Diffing against %s.', base)
    # git diff <commit>... is equivalent to
    # git diff $(git merge-base <commit> HEAD)
    return repo_manager_obj.get_git_diff(base + '...')

  def get_build_command(self, host_repo_path, image_repo_path):
    """Returns the command for building the project that is run inside the
    project builder container."""
    raise NotImplementedError('Child class must implement method.')

  def _build_external_project_docker_image(self, manager):
    """Helper for child classes that builds an external project's docker image.
    Returns a BuildPreparationResult indicating failure or success."""
    build_integration_abs_path = os.path.join(
        manager.repo_dir, self.config.build_integration_path)
    if not build_external_project_docker_image(manager.repo_dir,
                                               build_integration_abs_path):
      logging.error('Failed to build external project.')
      return get_build_preparation_failure()
    image_repo_path = os.path.join('/src', self.config.project_repo_name)
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)

  def _make_repo_storage_dir(self):
    os.makedirs(self.workspace.repo_storage, exist_ok=True)

  def _clone_repo_and_checkout(self, repo_url, repo_name):
    """Helper for child classes that clones the git repo specified by |repo_url|
    to |repo_name|, checks out the specified commit, and returns the
    |manager|."""
    self._make_repo_storage_dir()
    # Checkout project's repo in the shared volume.
    manager = repo_manager.clone_repo_and_get_manager(
        repo_url,
        self.workspace.repo_storage,
        repo_name=repo_name,
        username=self.config.actor,
        password=self.config.token)
    self._checkout_specified_commit(manager)
    return manager

  def _checkout_specified_commit(self, manager):
    checkout_specified_commit(manager, self.config.pr_ref, self.config.git_sha)

  def _detect_main_repo(self):
    """Helper for child classes that detects the main repo and returns a tuple
    containing the inffered url and path to the repo in the image."""
    inferred_url, image_repo_path = build_specified_commit.detect_main_repo(
        self.config.oss_fuzz_project_name,
        repo_name=self.config.project_repo_name)
    if not inferred_url or not image_repo_path:
      logging.error('Could not detect repo.')
    return inferred_url, image_repo_path

  def _create_repo_manager_for_project_src_path(self):
    """Returns a repo manager for |project_src_path|."""
    return repo_manager.RepoManager(self.config.project_src_path)


def get_build_command():
  """Returns the command to build the project inside the project builder
  container."""
  return 'compile'


def get_replace_repo_and_build_command(host_repo_path, image_repo_path):
  """Returns the command to replace the repo located at |image_repo_path| with
  |host_repo_path| and build the project inside the project builder
  container."""
  rm_path = os.path.join(image_repo_path, '*')
  image_src_path = os.path.dirname(image_repo_path)
  build_command = get_build_command()
  command = (f'cd / && rm -rf {rm_path} && cp -r {host_repo_path} '
             f'{image_src_path} && cd - && {build_command}')
  return command


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


def checkout_specified_commit(repo_manager_obj, pr_ref, git_sha):
  """Checks out the specified commit or pull request using
  |repo_manager_obj|."""
  try:
    if pr_ref:
      repo_manager_obj.checkout_pr(pr_ref)
    else:
      repo_manager_obj.checkout_commit(git_sha)
  except (RuntimeError, ValueError):
    logging.error(
        'Can not check out requested state %s. '
        'Using current repo state.', pr_ref or git_sha)


class GithubCiMixin:
  """Mixin for Github based CI systems."""

  def __init__(self, config):
    super().__init__(config)
    # Unlike in other classes, here _repo_dir is the parent directory of the
    # repo, not its actual directory.
    self._repo_dir = self.workspace.repo_storage

  @property
  def repo_dir(self):
    """Returns the source repo path, if it has been checked out. None is
    returned otherwise."""
    if not os.path.exists(self._repo_dir):
      logging.warning('Repo dir: %s does not exist.', self._repo_dir)
      return None

    # Note: this assumes there is only one repo checked out here.
    listing = os.listdir(self._repo_dir)
    if len(listing) != 1:
      raise RuntimeError('Invalid repo directory.')

    repo_path = os.path.join(self._repo_dir, listing[0])
    if not os.path.isdir(repo_path):
      raise RuntimeError('Repo is not a directory.')

    return repo_path


class InternalGithub(GithubCiMixin, BaseCi):
  """Class representing CI for an OSS-Fuzz project on Github Actions."""

  def _copy_repo_from_image(self, image_repo_path):
    self._make_repo_storage_dir()
    repo_name = os.path.basename(image_repo_path)
    host_repo_path = os.path.join(self._repo_dir, repo_name)
    bash_command = f'cp -r {image_repo_path} {host_repo_path}'
    docker_args, _ = docker.get_base_docker_run_args(
        self.workspace, self.config.sanitizer, self.config.language,
        self.config.docker_in_docker)
    docker_args.extend([
        docker.get_project_image_name(self.config.oss_fuzz_project_name),
        '/bin/bash', '-c', bash_command
    ])
    if not helper.docker_run(docker_args):
      raise RuntimeError('Failed to copy repo.')
    return repo_manager.RepoManager(host_repo_path)

  def prepare_for_fuzzer_build(self):
    """Builds the fuzzer builder image, checks out the pull request/commit and
    returns the BuildPreparationResult."""
    logging.info('InternalGithub: preparing for fuzzer build.')
    assert self.config.pr_ref or self.config.git_sha
    # _detect_main_repo builds the image as a side effect.
    _, image_repo_path = self._detect_main_repo()
    if not image_repo_path:
      return get_build_preparation_failure()

    # Use the same name used in the docker image so we can overwrite it.
    manager = self._copy_repo_from_image(image_repo_path)
    self._checkout_specified_commit(manager)
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)

  def get_build_command(self, host_repo_path, image_repo_path):  # pylint: disable=no-self-use
    """Returns the command for building the project that is run inside the
    project builder container. Command also replaces |image_repo_path| with
    |host_repo_path|."""
    return get_replace_repo_and_build_command(host_repo_path, image_repo_path)


def get_build_preparation_failure():
  """Returns a BuildPreparationResult indicating failure."""
  return BuildPreparationResult(success=False,
                                image_repo_path=None,
                                repo_manager=None)


class InternalGeneric(BaseCi):
  """Class representing CI for an OSS-Fuzz project on a CI other than Github
  actions."""

  def __init__(self, config):
    super().__init__(config)
    self._repo_dir = config.project_src_path

  @property
  def repo_dir(self):
    """Returns the source repo path, if it has been checked out. None is
    returned otherwise."""
    return self._repo_dir

  def prepare_for_fuzzer_build(self):
    """Builds the project builder image for an OSS-Fuzz project outside of
    GitHub actions. Returns the repo_manager. Does not checkout source code
    since external projects are expected to bring their own source code to
    CIFuzz."""
    logging.info('InternalGeneric: preparing for fuzzer build.')
    # detect_main_repo builds the image as a side effect.
    _, image_repo_path = self._detect_main_repo()

    if not image_repo_path:
      return get_build_preparation_failure()

    manager = self._create_repo_manager_for_project_src_path()
    return BuildPreparationResult(success=True,
                                  image_repo_path=image_repo_path,
                                  repo_manager=manager)

  def get_build_command(self, host_repo_path, image_repo_path):  # pylint: disable=no-self-use
    """Returns the command for building the project that is run inside the
    project builder container. Command also replaces |image_repo_path| with
    |host_repo_path|."""
    return get_replace_repo_and_build_command(host_repo_path, image_repo_path)


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

  def __init__(self, config):
    super().__init__(config)
    self._repo_dir = config.project_src_path

  @property
  def repo_dir(self):
    """Returns the source repo path, if it has been checked out. None is
    returned otherwise."""
    return self._repo_dir

  def prepare_for_fuzzer_build(self):
    logging.info('ExternalGeneric: preparing for fuzzer build.')
    manager = self._create_repo_manager_for_project_src_path()
    return self._build_external_project_docker_image(manager)

  def get_build_command(self, host_repo_path, image_repo_path):  # pylint: disable=no-self-use
    """Returns the command for building the project that is run inside the
    project builder container."""
    return get_build_command()


class ExternalGithub(GithubCiMixin, BaseCi):
  """Class representing CI for a non-OSS-Fuzz project on Github Actions."""

  def prepare_for_fuzzer_build(self):
    """Builds the project builder image for a non-OSS-Fuzz project on GitHub
    actions. Sets the repo manager. Does not checkout source code since external
    projects are expected to bring their own source code to CIFuzz. Returns True
    on success."""
    logging.info('ExternalGithub: preparing for fuzzer build.')
    # Checkout before building, so we don't need to rely on copying the source
    # from the image.
    # TODO(metzman): Figure out if we want second copy at all.
    manager = self._clone_repo_and_checkout(self.config.git_url,
                                            self.config.project_repo_name)
    return self._build_external_project_docker_image(manager)

  def get_build_command(self, host_repo_path, image_repo_path):  # pylint: disable=no-self-use
    """Returns the command for building the project that is run inside the
    project builder container."""
    return get_build_command()
