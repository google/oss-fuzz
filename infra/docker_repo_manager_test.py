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
"""Test the functionality of the RepoManager class
The will consist of the following functional tests
  1. Cloning of directory in desired location
  2. Checking out a specific commit
  3. Can get a list of commits between two SHAs
"""

from DockerRepoManager import DockerRepoManager as drm
import unittest


class TestRepoManager(unittest.TestCase):
  """Class to test the functionality of the RepoManager class."""

  project_name = 'curl'

  def test_constructor(self):
    """Tests docker repo manager initilization."""
    curl_drm = drm(self.project_name)
    self.assertEqual(curl_drm.docker_image, 'gcr.io/oss-fuzz/curl')
    self.assertEqual(curl_drm.repo_url, 'https://github.com/curl/curl.git')
    self.assertEqual(curl_drm.src_on_image, '/src/curl')

  def test_get_image_commit(self):
    """Test that a specific commit can be transfered into a docker image."""
    curl_drm = drm(self.project_name)
    commit_to_test = 'bc5d22c3dede2f04870c37aec9a50474c4b888ad'
    curl_drm.set_image_commit(commit_to_test)
    self.assertEqual(curl_drm.get_image_commit(), commit_to_test)


if __name__ == '__main__':
  unittest.main()
