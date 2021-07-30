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
"""Tests for helper.py"""

import datetime
import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import helper
import templates

# pylint: disable=no-self-use,protected-access


class ShellTest(unittest.TestCase):
  """Tests 'shell' command."""

  @mock.patch('helper.docker_run')
  @mock.patch('helper.build_image_impl')
  def test_base_runner_debug(self, mocked_build_image_impl, _):
    """Tests that shell base-runner-debug works as intended."""
    image_name = 'base-runner-debug'
    unparsed_args = ['shell', image_name]
    parser = helper.get_parser()
    args = helper.parse_args(parser, unparsed_args)
    args.sanitizer = 'address'
    result = helper.shell(args)
    mocked_build_image_impl.assert_called_with(image_name, None, None)
    self.assertTrue(result)


class BuildImageImplTest(unittest.TestCase):
  """Tests for build_image_impl."""

  @mock.patch('helper.docker_build')
  def test_no_cache(self, mocked_docker_build):
    """Tests that cache=False is handled properly."""
    image_name = 'base-image'
    helper.build_image_impl(image_name, cache=False)
    self.assertIn('--no-cache', mocked_docker_build.call_args_list[0][0][0])

  @mock.patch('helper.docker_build')
  @mock.patch('helper.pull_images')
  def test_pull(self, mocked_pull_images, _):
    """Tests that pull=True is handled properly."""
    image_name = 'base-image'
    helper.build_image_impl(image_name, pull=True)
    mocked_pull_images.assert_called_with()

  @mock.patch('helper.docker_build')
  def test_base_image(self, mocked_docker_build):
    """Tests that build_image_impl works as intended with a base-image."""
    image_name = 'base-image'
    helper.build_image_impl(image_name)
    mocked_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz-base/base-image', 'infra/base-images/base-image'
    ])

  @mock.patch('helper.docker_build')
  def test_oss_fuzz_project(self, mocked_docker_build):
    """Tests that build_image_impl works as intended with an OSS-Fuzz
    project."""
    image_name = 'example'
    helper.build_image_impl(image_name)
    mocked_docker_build.assert_called_with(
        ['-t', 'gcr.io/oss-fuzz/example', 'projects/example'])

  @mock.patch('helper.docker_build')
  def test_external_project(self, mocked_docker_build):
    """Tests that build_image_impl works as intended with a non-OSS-Fuzz
    project."""
    image_name = 'example'
    project_src_path = '/project-src'
    build_integration_path = '/project-src/build-integration'
    helper.build_image_impl(image_name, project_src_path,
                            build_integration_path)
    mocked_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz/example', '--file',
        '/project-src/build-integration/Dockerfile', '/project-src'
    ])


class GenerateImplTest(fake_filesystem_unittest.TestCase):
  """Tests for _generate_impl."""
  PROJECT_NAME = 'newfakeproject'

  def setUp(self):
    self.setUpPyfakefs()
    self.fs.add_real_directory(helper.OSS_FUZZ_DIR)

  def _verify_templated_files(self, template_dict, directory):
    template_args = {'project_name': self.PROJECT_NAME, 'year': 2021}
    for filename, template in template_dict.items():
      file_path = os.path.join(directory, filename)
      with open(file_path, 'r') as file_handle:
        contents = file_handle.read()
      self.assertEqual(contents, template % template_args)

  @mock.patch('helper._get_current_datetime',
              return_value=datetime.datetime(year=2021, month=1, day=1))
  def test_generate_oss_fuzz_project(self, _):
    """Tests that the correct files are generated for an OSS-Fuzz project."""
    helper._generate_impl(self.PROJECT_NAME, None)
    self._verify_templated_files(templates.TEMPLATES,
                                 os.path.join('projects', self.PROJECT_NAME))

  def test_generate_external_project(self):
    """Tests that the correct files are generated for a non-OSS-Fuzz project."""
    build_integration_path = '/project-src/build-integration'
    helper._generate_impl(self.PROJECT_NAME, build_integration_path)
    self._verify_templated_files(templates.EXTERNAL_TEMPLATES,
                                 build_integration_path)
