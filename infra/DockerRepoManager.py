# Copyright 2019 Google LLC
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
"""Class to manage a git repos interaction with a docker image.

This class is to be used to manage Oss-Fuzz projects docker build images.
It allows for a build image to be build with a specific commit rather
than just the current head of the repo.

  Typical usage example:

    drm = DockerRepoManager('curl')
    current_commit = drm.get_image_commit()
    drm.checkout_commit('df26f5f9c36e19cd503c0e462e9f72ad37b84c82')

"""
import os

from helper import build_image_impl
from helper import check_project_exists
from helper import get_dockerfile_path
from helper import is_base_image
from RepoManager import RepoManager


class NoRepoFoundError(Exception):
  """Occurs when the bisector cant infer the main repo."""
  pass


class DockerRepoManagerError(Exception):
  """When there is a docker error of execution"""
  pass


class DockerRepoManager(RepoManager):
  """Class to manage a git repo inside of a docker continer.

  Attributes:
    docker_image: The name of the docker image that is being modified
    project_name: The name of the project associated with the docker image
    src_on_image: The file path where the main repo is located on the image
    TEMP_CONTAINER: The name of the temp container to overwrite the with
      the new commit
  """

  TEMP_CONTAINER = 'temp_container'

  def __init__(self, project_name):
    """Inits the DockerRepoManager class.

      Args:
        project_name: The name of the project that is associated with the image
    """
    self.project_name = project_name
    self.docker_image = self._get_docker_image_name()
    repo_url = self._infer_main_repo()
    self.src_on_image = os.path.join('/src', project_name)
    super().__init__(repo_url)
    if self.repo_name != project_name:
      raise DockerRepoManagerError(
          'Error, the project name must be the same as the ' +
          'git repo name but are %s and %s' % (project_name, super().repo_name))

  def cleanup(self):
    """Removes old  TEMP_CONTAINER."""
    self._run_command(['docker', 'stop', self.TEMP_CONTAINER])
    self._run_command(['docker', 'container', 'rm', self.TEMP_CONTAINER])

  def checkout_commit(self, commit):
    super().checkout_commit(commit)
    self._set_image_commit(commit)


  def _set_image_commit(self, commit):
    """Creates a docker image with a specified commit as its source.

    Args:
      commit: The SHA the source is to be checked out at

    Raises:
      DockerRepoManagerError: when the commit is not successfully
      mounted to the image
    """
    self.cleanup()
    # Remove all previous images
    self._run_command(['docker', 'rmi', self.docker_image])

    # Build builder image
    build_image_impl(self.project_name)
    mount_command = [
        'docker', 'create', '--name', self.TEMP_CONTAINER, self.docker_image
    ]
    self._run_command(mount_command)

    # Start the container to be modified
    self._run_command(['docker', 'start', self.TEMP_CONTAINER])

    # Remove outdated source repo from container
    remove_command = [
        'docker', 'exec', self.TEMP_CONTAINER, 'rm', '-rf', self.src_on_image
    ]
    self._run_command(remove_command)

    # Copy updated source repo to container
    copy_command = [
        'docker', 'cp',
        os.path.join(self.repo_dir, '.'),
        self.TEMP_CONTAINER + ':' + self.src_on_image
    ]
    self._run_command(copy_command)

    # Overwrite current image with new container mount
    commit_command = [
        'docker', 'commit', self.TEMP_CONTAINER, self.docker_image
    ]
    self._run_command(commit_command)

    # Check the command executed correctly
    image_commit = self.get_image_commit()
    if not image_commit == commit:
      raise DockerRepoManagerError(
          'Docker commit checkout current: %s desired: %s' % (image_commit,
                                                              commit))

  def get_image_commit(self):
    """Gets the current commit SHA from the docker image.

    Returns:
      Commit sha or None on error
    """
    get_commit_command = [
        'docker', 'run', '--rm', '-it', self.docker_image, 'git', '--git-dir',
        os.path.join(self.src_on_image, '.git'), 'rev-parse', 'HEAD'
    ]

    out, err = self._run_command(get_commit_command)
    if err is not None:
      return None
    return str(out).rstrip()

  def _get_docker_image_name(self):
    """Gets the name of the docker build image for specified repo.

    Returns:
      The name of the docker build image
    """
    proj_is_base_image = is_base_image(self.project_name)
    if proj_is_base_image:
      image_project = 'oss-fuzz-base'
    else:
      image_project = 'oss-fuzz'
    return 'gcr.io/%s/%s' % (image_project, self.project_name)

  def _infer_main_repo(self):
    """ Trys to guess the main repo of the project based on the Dockerfile.

    Returns:
      The guessed repo url path

    Raises:
      NoRepoFoundError: if the repo can't be inferred
    """
    if not check_project_exists(self.project_name):
      raise NoRepoFoundError(
          'No project could be found with name %s' % self.project_name)
    docker_path = get_dockerfile_path(self.project_name)
    with open(docker_path, 'r') as fp:
      for line in fp.readlines():
        for part_command in line.split(' '):
          if '/' + str(self.project_name) + '.git' in part_command:
            return part_command.rstrip()
          if 'git:' in part_command and '/' + str(self.project_name) in part_command:
            return part_command.rstrip()

    raise NoRepoFoundError(
        'No repos were found with name %s in docker file %s' %
        (self.project_name, docker_path))
