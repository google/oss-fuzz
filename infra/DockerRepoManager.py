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
    drm.set_image_commit('df26f5f9c36e19cd503c0e462e9f72ad37b84c82')

"""
from helper import _build_image
from helper import _check_project_exists
from helper import _get_dockerfile_path
from helper import _is_base_image
from RepoManager import RepoManager
from RepoManager import RepoManagerException
import os


class NoRepoFoundException(Exception):
  """Occurs when the bisector cant infer the main repo."""
  pass


class DockerRepoManagerException(Exception):
  """When there is a docker error of execution"""
  pass


class DockerRepoManager(RepoManager):
  """Class to manage a git repo inside of a docker continer.

  Attributes:
    docker_image: The name of the docker image that is being modified
    project_name: The name of the project associated with the docker image
  """

  docker_image = ''
  project_name = ''
  src_on_image = ''
  TEMP_IMAGE_NAME = 'temp_container'

  def __init__(self, project_name, example_commit=None):
    """Inits the DockerRepoManager class.

      Args:
        project_name: The name of the project that is associated with the image
    """
    self.project_name = project_name
    self.docker_image = self._get_docker_image_name()
    repo_url = self._infer_main_repo(example_commit)
    self.src_on_image = os.path.join('/src', project_name)
    super().__init__(repo_url)
    if self.repo_name != project_name:
      raise DockerRepoManagerException(
          'Error, the project name must be the same as the ' +
          'git repo name but are %s and %s' % (project_name, super().repo_name))

  def set_image_commit(self, commit):
    """Creates a docker image with a specified commit as its source.

    Args:
      commit: The SHA the source is to be checked out at

    Raises:
      DockerRepoManagerException: when the commit is not successfully
      mounted to the image
    """

    #Remove old temp container
    stop_command = ['docker', 'stop', self.TEMP_IMAGE_NAME]
    self._run_command(stop_command)
    remove_command = ['docker', 'container', 'rm', self.TEMP_IMAGE_NAME]
    self._run_command(remove_command)

    # Remove all previous images
    rmi_command = ['docker', 'rmi', self.docker_image]
    self._run_command(rmi_command)

    # Build builder image
    _build_image(self.project_name)
    self.checkout_commit(commit)
    mount_command = [
        'docker', 'create', '--name', self.TEMP_IMAGE_NAME, self.docker_image
    ]
    self._run_command(mount_command)

    # Start the container to be modified
    start_container = [
      'docker', 'start', self.TEMP_IMAGE_NAME
    ]
    self._run_command(start_container)

    # Remove outdated source repo from container
    remove_command = [
        'docker', 'exec', self.TEMP_IMAGE_NAME, 'rm', '-rf', self.src_on_image
    ]
    self._run_command(remove_command)

    # Copy updated source repo to container
    copy_command = [
        'docker', 'cp',
        os.path.join(self.full_path, '.'),
        self.TEMP_IMAGE_NAME + ':' + self.src_on_image
    ]
    self._run_command(copy_command)

    # Overwrite current image with new container mount
    commit_command = [
        'docker', 'commit', self.TEMP_IMAGE_NAME, self.docker_image
    ]
    self._run_command(commit_command)

    # Check the command executed correctly
    image_commit = self.get_image_commit()
    if not image_commit == commit:
      raise DockerRepoManagerException(
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
    is_base_image = _is_base_image(self.project_name)
    if is_base_image:
      image_project = 'oss-fuzz-base'
    else:
      image_project = 'oss-fuzz'
    return 'gcr.io/%s/%s' % (image_project, self.project_name)

  def _infer_main_repo(self, example_commit=None):
    """ Trys to guess the main repo of the project based on the Dockerfile.

    Args:
      example_commit: A commit that is in the main repos tree

    Returns:
      The guessed repo url path

    Raises:
      NoRepoFoundException: if the repo can't be inferred
    """
    if not _check_project_exists(self.project_name):
      raise NoRepoFoundException(
          'No project could be found with name %s' % self.project_name)
    docker_path = _get_dockerfile_path(self.project_name)
    with open(docker_path, 'r') as fp:

      # Use generic git format and project name to guess main repo
      if example_commit is None:
        for line in fp.readlines():
          line.lower()
          for part_command in line.split(' '):
            if '/' + str(self.project_name) + '.git' in part_command:
              return part_command.rstrip()
            if 'git:' in part_command and '/' + str(self.project_name) in part_command:
              return part_command.rstrip()

      # Use example commit SHA to guess main repo
      else:
        for line in fp.readlines():
          if 'clone' in line:
            for git_repo_url in line.split(' '):
              if 'http' in git_repo_url:
                try:
                  rm = RepoManager(git_repo_url.rstrip())
                  if rm.commit_exists(example_commit):
                    return git_repo_url
                except RepoManagerException as e:
                  print('%s is not the main git repo: %s' % (git_repo_url, str(e)))


    raise NoRepoFoundException(
        'No repos were found with name %s in docker file %s' %
        (self.project_name, docker_path))
