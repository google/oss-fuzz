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
import clusterfuzz_deployment
import continuous_integration
import docker

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helper

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


def check_project_src_path(project_src_path):
  """Returns True if |project_src_path| exists."""
  if not os.path.exists(project_src_path):
    logging.error(
        'PROJECT_SRC_PATH: %s does not exist. '
        'Are you mounting it correctly?', project_src_path)
    return False
  return True


# pylint: disable=too-many-arguments


class Builder:  # pylint: disable=too-many-instance-attributes
  """Class for fuzzer builders."""

  def __init__(self, config, ci_system):
    self.config = config
    self.ci_system = ci_system
    self.workspace = docker.Workspace(config)
    self.workspace.initialize_dir(self.workspace.out)
    self.workspace.initialize_dir(self.workspace.work)
    self.clusterfuzz_deployment = (
        clusterfuzz_deployment.get_clusterfuzz_deployment(
            self.config, self.workspace))
    self.image_repo_path = None
    self.host_repo_path = None
    self.repo_manager = None

  def build_image_and_checkout_src(self):
    """Builds the project builder image and checkout source code for the patch
    we want to fuzz (if necessary). Returns True on success.
    Must be implemented by child classes."""
    result = self.ci_system.prepare_for_fuzzer_build()
    if not result.success:
      return False
    self.image_repo_path = result.image_repo_path
    self.repo_manager = result.repo_manager
    logging.info('repo_dir: %s.', self.repo_manager.repo_dir)
    self.host_repo_path = self.repo_manager.repo_dir
    return True

  def build_fuzzers(self):
    """Moves the source code we want to fuzz into the project builder and builds
    the fuzzers from that source code. Returns True on success."""
    docker_args, docker_container = docker.get_base_docker_run_args(
        self.workspace, self.config.sanitizer, self.config.language)
    if not docker_container:
      docker_args.extend(
          _get_docker_build_fuzzers_args_not_container(self.host_repo_path))

    if self.config.sanitizer == 'memory':
      docker_args.extend(
          _get_docker_build_fuzzers_args_msan(self.workspace.work))
      self.handle_msan_prebuild(docker_container)

    docker_args.extend([
        docker.get_project_image_name(self.config.project_name),
        '/bin/bash',
        '-c',
    ])
    rm_path = os.path.join(self.image_repo_path, '*')
    image_src_path = os.path.dirname(self.image_repo_path)
    bash_command = (f'rm -rf {rm_path} && cp -r {self.host_repo_path} '
                    f'{image_src_path} && compile')
    docker_args.append(bash_command)
    logging.info('Building with %s sanitizer.', self.config.sanitizer)

    # TODO(metzman): Stop using helper.docker_run so we can get rid of
    # docker.get_base_docker_run_args and merge its contents into
    # docker.get_base_docker_run_command.
    if not helper.docker_run(docker_args):
      logging.error('Building fuzzers failed.')
      return False

    if self.config.sanitizer == 'memory':
      self.handle_msan_postbuild(docker_container)
    return True

  def handle_msan_postbuild(self, container):
    """Post-build step for MSAN builds. Patches the build to use MSAN
    libraries."""
    helper.docker_run([
        '--volumes-from', container, '-e', f'WORK={self.workspace.work}',
        docker.MSAN_LIBS_BUILDER_TAG, 'patch_build.py', '/out'
    ])

  def handle_msan_prebuild(self, container):
    """Pre-build step for MSAN builds. Copies MSAN libs to |msan_libs_dir| and
    returns docker arguments to use that directory for MSAN libs."""
    logging.info('Copying MSAN libs.')
    helper.docker_run([
        '--volumes-from', container, docker.MSAN_LIBS_BUILDER_TAG, 'bash', '-c',
        f'cp -r /msan {self.workspace.work}'
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
    if self.config.keep_unaffected_fuzz_targets:
      logging.info('Not removing unaffected fuzz targets.')
      return True

    logging.info('Removing unaffected fuzz targets.')
    changed_files = self.ci_system.get_changed_code_under_test(
        self.repo_manager)
    affected_fuzz_targets.remove_unaffected_fuzz_targets(
        self.clusterfuzz_deployment, self.workspace.out, changed_files,
        self.image_repo_path)
    return True


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
  ci_system = continuous_integration.get_ci(config)
  logging.info('ci_system: %s.', ci_system)
  builder = Builder(config, ci_system)
  return builder.build()


def check_fuzzer_build(workspace,
                       sanitizer,
                       language,
                       allowed_broken_targets_percentage=None):
  """Checks the integrity of the built fuzzers.

  Args:
    out_dir: The directory containing the fuzzer binaries.
    sanitizer: The sanitizer the fuzzers are built with.

  Returns:
    True if fuzzers are correct.
  """
  if not os.path.exists(workspace.out):
    logging.error('Invalid out directory: %s.', workspace.out)
    return False
  if not os.listdir(workspace.out):
    logging.error('No fuzzers found in out directory: %s.', workspace.out)
    return False

  docker_args, _ = docker.get_base_docker_run_args(workspace, sanitizer,
                                                   language)
  if allowed_broken_targets_percentage is not None:
    docker_args += [
        '-e',
        ('ALLOWED_BROKEN_TARGETS_PERCENTAGE=' +
         allowed_broken_targets_percentage)
    ]

  docker_args.extend(['-t', docker.BASE_RUNNER_TAG, 'test_all.py'])
  result = helper.docker_run(docker_args)
  if not result:
    logging.error('Check fuzzer build failed.')
    return False
  return True


def _get_docker_build_fuzzers_args_not_container(host_repo_path):
  """Returns arguments to the docker build arguments that are needed to use
  |host_repo_path| when the host of the OSS-Fuzz builder container is not
  another container."""
  return ['-v', f'{host_repo_path}:{host_repo_path}']


def _get_docker_build_fuzzers_args_msan(work_dir):
  """Returns arguments to the docker build command that are needed to use
  MSAN."""
  # TODO(metzman): MSAN is broken, fix.
  msan_libs_path = os.path.join(work_dir, 'msan')
  return ['-e', f'MSAN_LIBS_PATH={msan_libs_path}']
