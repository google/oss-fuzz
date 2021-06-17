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

import docker


class GetProjectImageTest(unittest.TestCase):
  """Tests for get_project_image."""

  def test_get_project_image(self):
    """Tests that get_project_image_name works as intended."""
    project = 'my-project'
    self.assertEqual(docker.get_project_image_name(project), 'gcr.io/oss-fuzz/my-project')

class GetDeleteImages(unittest.TestCase):
  """Tests for delete_images."""

  @mock.patch('utils.execute')
  def test_delete_images(self, mocked_execute):
    """Tests that get_project_image_name works as intended."""
    images = ['image']
    docker.delete_images(images)
    expected_calls = [
        mock.call(['docker', 'rmi', '-f'] + images),
        mock.call(['docker', 'builder', 'prune', '-f'])
    ]

    mocked_execute.assert_has_calls(expected_calls)
