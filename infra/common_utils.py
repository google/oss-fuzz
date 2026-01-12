# Copyright 2025 Google LLC
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
"""Common utilities for OSS-Fuzz infrastructure."""

import logging
import os
import re
import shlex
import subprocess

import constants

OSS_FUZZ_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

BASE_RUNNER_IMAGE = 'gcr.io/oss-fuzz-base/base-runner'

BASE_IMAGES = {
    'generic': [
        'gcr.io/oss-fuzz-base/base-image',
        'gcr.io/oss-fuzz-base/base-clang',
        'gcr.io/oss-fuzz-base/base-builder',
        BASE_RUNNER_IMAGE,
        'gcr.io/oss-fuzz-base/base-runner-debug',
    ],
    'go': ['gcr.io/oss-fuzz-base/base-builder-go'],
    'javascript': ['gcr.io/oss-fuzz-base/base-builder-javascript'],
    'jvm': ['gcr.io/oss-fuzz-base/base-builder-jvm'],
    'python': ['gcr.io/oss-fuzz-base/base-builder-python'],
    'rust': ['gcr.io/oss-fuzz-base/base-builder-rust'],
    'ruby': ['gcr.io/oss-fuzz-base/base-builder-ruby'],
    'swift': ['gcr.io/oss-fuzz-base/base-builder-swift'],
}

PROJECT_LANGUAGE_REGEX = re.compile(r'\s*language\s*:\s*([^\s]+)')
BASE_OS_VERSION_REGEX = re.compile(r'\s*base_os_version\s*:\s*([^\s]+)')

logger = logging.getLogger(__name__)


def get_project_build_subdir(project, subdir_name):
  """Creates the |subdir_name| subdirectory of the |project| subdirectory in
  |BUILD_DIR| and returns its path."""
  directory = os.path.join(BUILD_DIR, subdir_name, project)
  os.makedirs(directory, exist_ok=True)

  return directory


def get_out_dir(project=''):
  """Creates and returns path to /out directory for the given project (if
  specified)."""
  return get_project_build_subdir(project, 'out')


class Project:
  """Class representing a project that is in OSS-Fuzz or an external project
  (ClusterFuzzLite user)."""

  def __init__(
      self,
      project_name_or_path,
      is_external=False,
      build_integration_path=constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH):
    self.is_external = is_external
    if self.is_external:
      self.path = os.path.abspath(project_name_or_path)
      self.name = os.path.basename(self.path)
      self.build_integration_path = os.path.join(self.path,
                                                 build_integration_path)
    else:
      self.name = project_name_or_path
      self.path = os.path.join(OSS_FUZZ_DIR, 'projects', self.name)
      self.build_integration_path = self.path

  @property
  def dockerfile_path(self):
    """Returns path to the project Dockerfile."""
    return os.path.join(self.build_integration_path, 'Dockerfile')

  @property
  def language(self):
    """Returns project language."""
    project_yaml_path = os.path.join(self.build_integration_path,
                                     'project.yaml')
    if not os.path.exists(project_yaml_path):
      logger.warning('No project.yaml. Assuming c++.')
      return constants.DEFAULT_LANGUAGE

    with open(project_yaml_path) as file_handle:
      content = file_handle.read()
      for line in content.splitlines():
        match = PROJECT_LANGUAGE_REGEX.match(line)
        if match:
          return match.group(1)

    logger.warning('Language not specified in project.yaml. Assuming c++.')
    return constants.DEFAULT_LANGUAGE

  @property
  def base_os_version(self):
    """Returns the project's base OS version."""
    project_yaml_path = os.path.join(self.build_integration_path,
                                     'project.yaml')
    if not os.path.exists(project_yaml_path):
      return 'legacy'

    with open(project_yaml_path) as file_handle:
      content = file_handle.read()
      for line in content.splitlines():
        match = BASE_OS_VERSION_REGEX.match(line)
        if match:
          return match.group(1)

    return 'legacy'

  @property
  def coverage_extra_args(self):
    """Returns project coverage extra args."""
    project_yaml_path = os.path.join(self.build_integration_path,
                                     'project.yaml')
    if not os.path.exists(project_yaml_path):
      logger.warning('project.yaml not found: %s.', project_yaml_path)
      return ''

    with open(project_yaml_path) as file_handle:
      content = file_handle.read()

    coverage_flags = ''
    read_coverage_extra_args = False
    # Pass the yaml file and extract the value of the coverage_extra_args key.
    # This is naive yaml parsing and we do not handle comments at this point.
    for line in content.splitlines():
      if read_coverage_extra_args:
        # Break reading coverage args if a new yaml key is defined.
        if len(line) > 0 and line[0] != ' ':
          break
        coverage_flags += line
      if 'coverage_extra_args' in line:
        read_coverage_extra_args = True
        # Include the first line only if it's not a multi-line value.
        if 'coverage_extra_args: >' not in line:
          coverage_flags += line.replace('coverage_extra_args: ', '')
    return coverage_flags

  @property
  def out(self):
    """Returns the out dir for the project. Creates it if needed."""
    return get_out_dir(self.name)

  @property
  def work(self):
    """Returns the out dir for the project. Creates it if needed."""
    return get_project_build_subdir(self.name, 'work')

  @property
  def corpus(self):
    """Returns the out dir for the project. Creates it if needed."""
    return get_project_build_subdir(self.name, 'corpus')


def is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def check_project_exists(project):
  """Checks if a project exists."""
  if os.path.exists(project.path):
    return True

  if project.is_external:
    descriptive_project_name = project.path
  else:
    descriptive_project_name = project.name

  logger.error('"%s" does not exist.', descriptive_project_name)
  return False


def get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(shlex.quote(part) for part in command)


def docker_build(build_args):
  """Calls `docker build`."""
  command = ['docker', 'build']
  command.extend(build_args)
  logger.info('Running: %s.', get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    logger.error('Docker build failed.')
    return False

  return True


def docker_pull(image):
  """Call `docker pull`."""
  command = ['docker', 'pull', image]
  logger.info('Running: %s', get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    logger.error('Docker pull failed.')
    return False

  return True


def pull_images(language=None):
  """Pulls base images used to build projects in language lang (or all if lang
  is None)."""
  for base_image_lang, base_images in BASE_IMAGES.items():
    if (language is None or base_image_lang == 'generic' or
        base_image_lang == language):
      for base_image in base_images:
        if not docker_pull(base_image):
          return False

  return True


def build_image_impl(project, cache=True, pull=False, architecture='x86_64'):
  """Builds image."""
  image_name = project.name

  if is_base_image(image_name):
    image_project = 'oss-fuzz-base'
    docker_build_dir = os.path.join(OSS_FUZZ_DIR, 'infra', 'base-images',
                                    image_name)
    dockerfile_path = os.path.join(docker_build_dir, 'Dockerfile')
  else:
    if not check_project_exists(project):
      return False
    dockerfile_path = project.dockerfile_path
    docker_build_dir = project.path
    image_project = 'oss-fuzz'

  if pull and not pull_images(project.language):
    return False

  build_args = []
  image_name = 'gcr.io/%s/%s' % (image_project, image_name)
  if architecture == 'aarch64':
    build_args += [
        'buildx',
        'build',
        '--platform',
        'linux/arm64',
        '--progress',
        'plain',
        '--load',
    ]
  if not cache:
    build_args.append('--no-cache')

  build_args += ['-t', image_name, '--file', dockerfile_path]
  build_args.append(docker_build_dir)

  if architecture == 'aarch64':
    command = ['docker'] + build_args
    subprocess.check_call(command)
    return True
  return docker_build(build_args)
