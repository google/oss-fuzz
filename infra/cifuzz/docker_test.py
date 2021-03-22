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
"""Tests the functionality of the fuzz_target module."""

import unittest
from unittest.mock import call
from unittest import mock


import docker


class TestGetProjectImageName(unittest.TestCase):
  """Tests for get_project_image_name."""

  def test_get_project_image_name(self):
    """Tests that get_project_image_name works as intended."""
    project_name = 'myproject'
    result = docker.get_project_image_name(project_name)
    self.assertEqual(result, 'gcr.io/oss-fuzz/myproject')


class TestDeleteImages(unittest.TestCase):
  """Tests for get_project_image_name."""

  @mock.patch('utils.execute')
  def test_delete_images(self, mocked_execute):
    """Tests thart delete_images deletes images."""
    images = ['myimage1', 'myimage2']
    docker.delete_images(images)
    mocked_execute.assert_has_calls([call(['docker', 'rmi', '-f'] + images),
                                     call(['docker', 'builder', 'prune', '-f'])])


class TestStopDockerContainer:
  """Tests for stop_docker_container."""
  @mock.patch('subprocess.run')
  def test_stop_docker_container(self, mocked_run):
    """Tests that stop_docker_container works as intended."""
    container_id = 'container-id'
    wait_time = 100
    result = docker.stop_docker_container(container_id, wait_time)
    mocked_run.assert_called_with(['docker', 'stop', container_id, '-t', str(wait_time)], check=False)
