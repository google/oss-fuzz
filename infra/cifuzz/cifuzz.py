# Copyright 2020 Google LLC
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
"""Module used by CI tools in order to interact with fuzzers. This module helps
CI tools to build fuzzers."""

import logging
import os
import sys

import affected_fuzz_targets
import change_under_test_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build_specified_commit
import helper
import repo_manager
import retry
import utils

# Default fuzz configuration.
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_ARCHITECTURE = 'x86_64'

# TODO(metzman): Turn default logging to WARNING when CIFuzz is stable.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

_IMAGE_BUILD_TRIES = 3
_IMAGE_BUILD_BACKOFF = 2


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


@retry.wrap(_IMAGE_BUILD_TRIES, _IMAGE_BUILD_BACKOFF)
def build_external_project_docker_image(project_name, project_src,
                                        build_integration_path):
  """Builds the project builder image for an external (non-OSS-Fuzz) project.
  Returns True on success."""
  dockerfile_path = os.path.join(build_integration_path, 'Dockerfile')
  tag = 'gcr.io/oss-fuzz/{project_name}'.format(project_name=project_name)
  command = ['-t', tag, '-f', dockerfile_path, project_src]
  return helper.docker_build(command)


def check_project_src_path(project_src_path):
  """Returns True if |project_src_path| exists."""
  if not os.path.exists(project_src_path):
    logging.error(
        'PROJECT_SRC_PATH: %s does not exist. '
        'Are you mounting it correctly?', project_src_path)
    return False
  return True


# pylint: disable=too-many-arguments


class BaseBuilder:  # pylint: disable=too-many-instance-attributes
  """Base class for fuzzer builders."""

  def __init__(self, config, host_repo_path=None):
    self.config = config
    self.out_dir = os.path.join(config.workspace, 'out')
    os.makedirs(self.out_dir, exist_ok=True)
    self.work_dir = os.path.join(config.workspace, 'work')
    os.makedirs(self.work_dir, exist_ok=True)
    self.host_repo_path = host_repo_path
    self.image_repo_path = None
    self.repo_manager = None

  def build_image_and_checkout_src(self):
    """Builds the project builder image and checkout source code for the patch
    we want to fuzz (if necessary). Returns True on success.
    Must be implemented by child classes."""
    raise NotImplementedError('Child class must implement method')

  def build_fuzzers(self):
    """Moves the source code we want to fuzz into the project builder and builds
    the fuzzers from that source code. Returns True on success."""
    docker_args = get_common_docker_args(self.config.sanitizer)
    container = utils.get_container_name()

    if container:
      docker_args.extend(
          _get_docker_build_fuzzers_args_container(self.out_dir, container))
    else:
      docker_args.extend(
          _get_docker_build_fuzzers_args_not_container(self.out_dir,
                                                       self.host_repo_path))

    if self.config.sanitizer == 'memory':
      docker_args.extend(_get_docker_build_fuzzers_args_msan(self.work_dir))
      self.handle_msan_prebuild(container)

    docker_args.extend([
        'gcr.io/oss-fuzz/' + self.config.project_name,
        '/bin/bash',
        '-c',
    ])
    rm_path = os.path.join(self.image_repo_path, '*')
    image_src_path = os.path.dirname(self.image_repo_path)
    bash_command = 'rm -rf {0} && cp -r {1} {2} && compile'.format(
        rm_path, self.host_repo_path, image_src_path)
    docker_args.append(bash_command)
    logging.info('Building with %s sanitizer.', self.config.sanitizer)
    if helper.docker_run(docker_args):
      # docker_run returns nonzero on failure.
      logging.error('Building fuzzers failed.')
      return False

    if self.config.sanitizer == 'memory':
      self.handle_msan_postbuild(container)
    return True

  def handle_msan_postbuild(self, container):
    """Post-build step for MSAN builds. Patches the build to use MSAN
    libraries."""
    helper.docker_run([
        '--volumes-from', container, '-e',
        'WORK={work_dir}'.format(work_dir=self.work_dir),
        'gcr.io/oss-fuzz-base/base-sanitizer-libs-builder', 'patch_build.py',
        '/out'
    ])

  def handle_msan_prebuild(self, container):
    """Pre-build step for MSAN builds. Copies MSAN libs to |msan_libs_dir| and
    returns docker arguments to use that directory for MSAN libs."""
    logging.info('Copying MSAN libs.')
    helper.docker_run([
        '--volumes-from', container, 'gcr.io/oss-fuzz-base/msan-libs-builder',
        'bash', '-c',
        'cp -r /msan {work_dir}'.format(work_dir=self.config.work_dir)
    ])

  def build(self):
    """Builds the image, checkouts the source (if needed), builds the fuzzers
    and then removes the unaffectted fuzzers. Returns True on success."""
    methods = [
        self.build_image_and_checkout_src, self.build_fuzzers,
        self.remove_unaffected_fuzz_targets
    ]
    for method in methods:
      if not method():
        return False
    return True

  def remove_unaffected_fuzz_targets(self):
    """Removes the fuzzers unaffected by the patch."""
    change_under_test = change_under_test_utils.ChangeUnderTest(
        self.config, self.repo_manager)
    changed_files = change_under_test.diff()
    affected_fuzz_targets.remove_unaffected_fuzz_targets(
        self.config.project_name, self.out_dir, changed_files,
        self.image_repo_path)
    return True


class ExternalGithubBuilder(BaseBuilder):
  """Class for building non-OSS-Fuzz projects on GitHub Actions."""

  def __init__(self, config):

    super().__init__(config, host_repo_path=config.project_src_path)
    self.build_integration_path = os.path.join(self.host_repo_path,
                                               config.build_integration_path)
    logging.info('build_integration_path %s, project_src_path %s.',
                 config.build_integration_path, self.host_repo_path)
    self.image_repo_path = os.path.join('/src', config.project_repo_name)

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager. Does not checkout source code since external projects are
    expected to bring their own source code to CIFuzz. Returns True on
    success."""
    logging.info('Building external project.')
    if not build_external_project_docker_image(self.config.project_name,
                                               self.host_repo_path,
                                               self.build_integration_path):
      logging.error('Failed to build external project.')
      return False
    self.repo_manager = repo_manager.RepoManager(self.host_repo_path)
    return True


class InternalGithubBuilder(BaseBuilder):
  """Class for building OSS-Fuzz projects on GitHub actions."""

  def __init__(self, config):
    # Validate inputs.
    assert config.pr_ref or config.commit_sha

    super().__init__(config)

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager and host_repo_path. Checks out source code of project with
    patch under test. Returns True on success."""
    logging.info('Building OSS-Fuzz project on Github Actions.')
    # detect_main_repo builds the image as a side effect.
    inferred_url, self.image_repo_path = (
        build_specified_commit.detect_main_repo(
            self.config.project_name, repo_name=self.config.project_repo_name))

    if not inferred_url or not self.image_repo_path:
      logging.error('Could not detect repo from project %s.',
                    self.config.project_name)
      return False

    git_workspace = os.path.join(self.config.workspace, 'storage')
    os.makedirs(git_workspace, exist_ok=True)

    # Use the same name used in the docker image so we can overwrite it.
    image_repo_name = os.path.basename(self.image_repo_path)

    # Checkout project's repo in the shared volume.
    self.repo_manager = repo_manager.clone_repo_and_get_manager(
        inferred_url, git_workspace, repo_name=image_repo_name)

    self.host_repo_path = self.repo_manager.repo_dir

    checkout_specified_commit(self.repo_manager, self.config.pr_ref,
                              self.config.commit_sha)
    return True


class InternalGenericCiBuilder(BaseBuilder):
  """Class for building fuzzers for an OSS-Fuzz project using on a platform
  other than GitHub actions."""

  def __init__(self, config):
    super().__init__(config, host_repo_path=config.project_src_path)

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager. Does not checkout source code since external projects are
    expected to bring their own source code to CIFuzz. Returns True on
    success."""
    logging.info('Building OSS-Fuzz project.')
    # detect_main_repo builds the image as a side effect.
    _, self.image_repo_path = (build_specified_commit.detect_main_repo(
        self.config.project_name, repo_name=self.config.project_repo_name))

    if not self.image_repo_path:
      logging.error('Could not detect repo from project %s.',
                    self.config.project_name)
      return False

    # Checkout project's repo in the shared volume.
    self.repo_manager = repo_manager.RepoManager(self.host_repo_path)
    return True


def get_builder(config):
  """Determines what kind of build is being requested using the arguments
  provided and instantiates and returns the correct builder object."""
  if config.platform == config.Platform.EXTERNAL_GITHUB:
    # Non-OSS-Fuzz projects must bring their own source and their own build
    # integration (which is relative to that source).
    return ExternalGithubBuilder(config)

  if config.platform == config.Platform.INTERNAL_GENERIC_CI:
    # Builds of OSS-Fuzz projects not hosted on Github must bring their own
    # source since the checkout logic CIFuzz implements is github-specific.
    # TODO(metzman): Consider moving Github-actions builds of OSS-Fuzz projects
    # to this system to reduce implementation complexity.
    return InternalGenericCiBuilder(config)

  return InternalGithubBuilder(config)


def build_fuzzers(config):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz project being built.
    project_repo_name: The name of the project's repo.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    pr_ref: The pull request reference to be built.
    commit_sha: The commit sha for the project to be built at.
    sanitizer: The sanitizer the fuzzers should be built with.

  Returns:
    True if build succeeded or False on failure.
  """
  # Do some quick validation.
  if config.project_src_path and not check_project_src_path(
      config.project_src_path):
    return False

  # Get the builder and then build the fuzzers.
  builder = get_builder(config)
  return builder.build()


def get_common_docker_args(sanitizer):
  """Returns a list of common docker arguments."""
  return [
      '--cap-add',
      'SYS_PTRACE',
      '-e',
      'FUZZING_ENGINE=' + DEFAULT_ENGINE,
      '-e',
      'SANITIZER=' + sanitizer,
      '-e',
      'ARCHITECTURE=' + DEFAULT_ARCHITECTURE,
      '-e',
      'CIFUZZ=True',
      '-e',
      'FUZZING_LANGUAGE=c++',  # FIXME: Add proper support.
  ]


def check_fuzzer_build(out_dir,
                       sanitizer='address',
                       allowed_broken_targets_percentage=None):
  """Checks the integrity of the built fuzzers.

  Args:
    out_dir: The directory containing the fuzzer binaries.
    sanitizer: The sanitizer the fuzzers are built with.

  Returns:
    True if fuzzers are correct.
  """
  if not os.path.exists(out_dir):
    logging.error('Invalid out directory: %s.', out_dir)
    return False
  if not os.listdir(out_dir):
    logging.error('No fuzzers found in out directory: %s.', out_dir)
    return False

  command = get_common_docker_args(sanitizer)

  if allowed_broken_targets_percentage is not None:
    command += [
        '-e',
        ('ALLOWED_BROKEN_TARGETS_PERCENTAGE=' +
         allowed_broken_targets_percentage)
    ]

  container = utils.get_container_name()
  if container:
    command += ['-e', 'OUT=' + out_dir, '--volumes-from', container]
  else:
    command += ['-v', '%s:/out' % out_dir]
  command.extend(['-t', 'gcr.io/oss-fuzz-base/base-runner', 'test_all.py'])
  exit_code = helper.docker_run(command)
  logging.info('check fuzzer build exit code: %d', exit_code)
  if exit_code:
    logging.error('Check fuzzer build failed.')
    return False
  return True


def _get_docker_build_fuzzers_args_container(host_out_dir, container):
  """Returns arguments to the docker build arguments that are needed to use
  |host_out_dir| when the host of the OSS-Fuzz builder container is another
  container."""
  return ['-e', 'OUT=' + host_out_dir, '--volumes-from', container]


def _get_docker_build_fuzzers_args_not_container(host_out_dir, host_repo_path):
  """Returns arguments to the docker build arguments that are needed to use
  |host_out_dir| when the host of the OSS-Fuzz builder container is not
  another container."""
  # !!! Test
  image_out_dir = '/out'
  return [
      '-e',
      'OUT=' + image_out_dir,
      '-v',
      '%s:%s' % (host_out_dir, image_out_dir),
      '-v',
      '%s:%s' % (host_repo_path, host_repo_path),
  ]


def _get_docker_build_fuzzers_args_msan(work_dir):
  """Returns arguments to the docker build command that are needed to use
  MSAN."""
  # TODO(metzman): MSAN is broken, fix.
  return [
      '-e', 'MSAN_LIBS_PATH={msan_libs_path}'.format(
          msan_libs_path=os.path.join(work_dir, 'msan'))
  ]
