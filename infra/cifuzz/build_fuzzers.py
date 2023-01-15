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
import base_runner_utils
import clusterfuzz_deployment
import continuous_integration
import docker
import logs
import workspace_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helper
import utils

logs.init()


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
    self.workspace = workspace_utils.Workspace(config)
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
    we want to fuzz (if necessary). Returns True on success."""
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
        self.workspace, self.config.sanitizer, self.config.language,
        self.config.architecture, self.config.docker_in_docker)
    if not docker_container:
      docker_args.extend(
          _get_docker_build_fuzzers_args_not_container(self.host_repo_path))

    build_command = self.ci_system.get_build_command(self.host_repo_path,
                                                     self.image_repo_path)

    # Set extra environment variables so that they are visible to the build.
    for key in self.config.extra_environment_variables:
      # Don't specify their value in case they get echoed.
      docker_args.extend(['-e', key])

    docker_args.extend([
        docker.get_project_image_name(self.config.oss_fuzz_project_name),
        '/bin/bash',
        '-c',
        build_command,
    ])
    logging.info('Building with %s sanitizer.', self.config.sanitizer)

    # TODO(metzman): Stop using helper.docker_run so we can get rid of
    # docker.get_base_docker_run_args and merge its contents into
    # docker.get_base_docker_run_command.
    if not helper.docker_run(docker_args):
      logging.error('Building fuzzers failed.')
      return False

    return True

  def upload_build(self):
    """Upload build."""
    if self.config.upload_build:
      self.clusterfuzz_deployment.upload_build(
          self.repo_manager.get_current_commit())

    return True

  def check_fuzzer_build(self):
    """Checks the fuzzer build. Returns True on success or if config specifies
    to skip check."""
    if not self.config.bad_build_check:
      return True

    return check_fuzzer_build(self.config)

  def build(self):
    """Builds the image, checkouts the source (if needed), builds the fuzzers
    and then removes the unaffectted fuzzers. Returns True on success."""
    methods = [
        self.build_image_and_checkout_src,
        self.build_fuzzers,
        self.remove_unaffected_fuzz_targets,
        self.upload_build,
        self.check_fuzzer_build,
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
    config: The configuration object for building fuzzers.

  Returns:
    True if build succeeded.
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


def check_fuzzer_build(config):
  """Checks the integrity of the built fuzzers.

  Args:
    config: The config object.

  Returns:
    True if fuzzers pass OSS-Fuzz's build check.
  """
  workspace = workspace_utils.Workspace(config)
  if not os.path.exists(workspace.out):
    logging.error('Invalid out directory: %s.', workspace.out)
    return False
  if not os.listdir(workspace.out):
    logging.error('No fuzzers found in out directory: %s.', workspace.out)
    return False

  env = base_runner_utils.get_env(config, workspace)
  if config.allowed_broken_targets_percentage is not None:
    env['ALLOWED_BROKEN_TARGETS_PERCENTAGE'] = (
        config.allowed_broken_targets_percentage)

  stdout, stderr, retcode = utils.execute('test_all.py', env=env)
  print(f'Build check: stdout: {stdout}\nstderr: {stderr}')
  if retcode == 0:
    logging.info('Build check passed.')
    return True
  logging.error('Build check failed.')
  return False


def _get_docker_build_fuzzers_args_not_container(host_repo_path):
  """Returns arguments to the docker build arguments that are needed to use
  |host_repo_path| when the host of the OSS-Fuzz builder container is not
  another container."""
  return ['-v', f'{host_repo_path}:{host_repo_path}']
