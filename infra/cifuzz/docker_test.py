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
"""Tests the functionality of the docker module."""
import unittest
from unittest import mock

import config_utils
import docker

CONTAINER_NAME = 'example-container'
config = config_utils.RunFuzzersConfig()
config.workspace = '/workspace'
WORKSPACE = docker.Workspace(config)
SANITIZER = 'example-sanitizer'
LANGUAGE = 'example-language'


class GetProjectImageTest(unittest.TestCase):
  """Tests for get_project_image."""

  def test_get_project_image(self):
    """Tests that get_project_image_name works as intended."""
    project = 'my-project'
    self.assertEqual(docker.get_project_image_name(project),
                     'gcr.io/oss-fuzz/my-project')


class GetDeleteImagesTest(unittest.TestCase):
  """Tests for delete_images."""

  @mock.patch('utils.execute')
  def test_delete_images(self, mocked_execute):  # pylint: disable=no-self-use
    """Tests that get_project_image_name works as intended."""
    images = ['image']
    docker.delete_images(images)
    expected_calls = [
        mock.call(['docker', 'rmi', '-f'] + images),
        mock.call(['docker', 'builder', 'prune', '-f'])
    ]

    mocked_execute.assert_has_calls(expected_calls)


class GetBaseDockerRunArgsTest(unittest.TestCase):
  """Tests get_base_docker_run_args."""

  @mock.patch('utils.get_container_name', return_value=CONTAINER_NAME)
  def test_get_base_docker_run_args_container(self, _):
    """Tests that get_base_docker_run_args works as intended when inside a
    container."""
    docker_args, docker_container = docker.get_base_docker_run_args(
        WORKSPACE, SANITIZER, LANGUAGE)
    self.assertEqual(docker_container, CONTAINER_NAME)
    expected_docker_args = []
    expected_docker_args = [
        '--cap-add',
        'SYS_PTRACE',
        '-e',
        'FUZZING_ENGINE=libfuzzer',
        '-e',
        'ARCHITECTURE=x86_64',
        '-e',
        'CIFUZZ=True',
        '-e',
        f'SANITIZER={SANITIZER}',
        '-e',
        f'FUZZING_LANGUAGE={LANGUAGE}',
        '-e',
        f'OUT={WORKSPACE.out}',
        '--volumes-from',
        CONTAINER_NAME,
    ]
    self.assertEqual(docker_args, expected_docker_args)

  @mock.patch('utils.get_container_name', return_value=None)
  def test_get_base_docker_run_args_no_container(self, _):
    """Tests that get_base_docker_run_args works as intended when not inside a
    container."""
    docker_args, docker_container = docker.get_base_docker_run_args(
        WORKSPACE, SANITIZER, LANGUAGE)
    self.assertEqual(docker_container, None)
    expected_docker_args = [
        '--cap-add', 'SYS_PTRACE', '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
        'ARCHITECTURE=x86_64', '-e', 'CIFUZZ=True', '-e',
        f'SANITIZER={SANITIZER}', '-e', f'FUZZING_LANGUAGE={LANGUAGE}', '-e',
        f'OUT={WORKSPACE.out}', '-v',
        f'{WORKSPACE.workspace}:{WORKSPACE.workspace}'
    ]
    self.assertEqual(docker_args, expected_docker_args)


class GetBaseDockerRunCommandTest(unittest.TestCase):
  """Tests get_base_docker_run_args."""

  @mock.patch('utils.get_container_name', return_value=None)
  def test_get_base_docker_run_command_no_container(self, _):
    """Tests that get_base_docker_run_args works as intended when not inside a
    container."""
    docker_args, docker_container = docker.get_base_docker_run_command(
        WORKSPACE, SANITIZER, LANGUAGE)
    self.assertEqual(docker_container, None)
    expected_docker_command = [
        'docker', 'run', '--rm', '--privileged', '--cap-add', 'SYS_PTRACE',
        '-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'ARCHITECTURE=x86_64', '-e',
        'CIFUZZ=True', '-e', f'SANITIZER={SANITIZER}', '-e',
        f'FUZZING_LANGUAGE={LANGUAGE}', '-e', f'OUT={WORKSPACE.out}', '-v',
        f'{WORKSPACE.workspace}:{WORKSPACE.workspace}'
    ]
    self.assertEqual(docker_args, expected_docker_command)
