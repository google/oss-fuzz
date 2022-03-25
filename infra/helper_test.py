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
import tempfile
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import constants
import helper
import templates

# pylint: disable=no-self-use,protected-access


class ShellTest(unittest.TestCase):
  """Tests 'shell' command."""

  @mock.patch('helper.docker_run')
  @mock.patch('helper.build_image_impl')
  def test_base_runner_debug(self, _, __):
    """Tests that shell base-runner-debug works as intended."""
    image_name = 'base-runner-debug'
    unparsed_args = ['shell', image_name]
    parser = helper.get_parser()
    args = helper.parse_args(parser, unparsed_args)
    args.sanitizer = 'address'
    result = helper.shell(args)
    self.assertTrue(result)


class BuildImageImplTest(unittest.TestCase):
  """Tests for build_image_impl."""

  @mock.patch('helper.docker_build')
  def test_no_cache(self, mock_docker_build):
    """Tests that cache=False is handled properly."""
    image_name = 'base-image'
    helper.build_image_impl(helper.Project(image_name), cache=False)
    self.assertIn('--no-cache', mock_docker_build.call_args_list[0][0][0])

  @mock.patch('helper.docker_build')
  @mock.patch('helper.pull_images')
  def test_pull(self, mock_pull_images, _):
    """Tests that pull=True is handled properly."""
    image_name = 'base-image'
    project = helper.Project(image_name, is_external=True)
    self.assertTrue(helper.build_image_impl(project, pull=True))
    mock_pull_images.assert_called_with('c++')

  @mock.patch('helper.docker_build')
  def test_base_image(self, mock_docker_build):
    """Tests that build_image_impl works as intended with a base-image."""
    image_name = 'base-image'
    self.assertTrue(helper.build_image_impl(helper.Project(image_name)))
    build_dir = os.path.join(helper.OSS_FUZZ_DIR,
                             'infra/base-images/base-image')
    mock_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz-base/base-image', '--file',
        os.path.join(build_dir, 'Dockerfile'), build_dir
    ])

  @mock.patch('helper.docker_build')
  def test_oss_fuzz_project(self, mock_docker_build):
    """Tests that build_image_impl works as intended with an OSS-Fuzz
    project."""
    project_name = 'example'
    self.assertTrue(helper.build_image_impl(helper.Project(project_name)))
    build_dir = os.path.join(helper.OSS_FUZZ_DIR, 'projects', project_name)
    mock_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz/example', '--file',
        os.path.join(build_dir, 'Dockerfile'), build_dir
    ])

  @mock.patch('helper.docker_build')
  def test_external_project(self, mock_docker_build):
    """Tests that build_image_impl works as intended with a non-OSS-Fuzz
    project."""
    with tempfile.TemporaryDirectory() as temp_dir:
      project_src_path = os.path.join(temp_dir, 'example')
      os.mkdir(project_src_path)
      build_integration_path = 'build-integration'
      project = helper.Project(project_src_path,
                               is_external=True,
                               build_integration_path=build_integration_path)
      self.assertTrue(helper.build_image_impl(project))
      mock_docker_build.assert_called_with([
          '-t', 'gcr.io/oss-fuzz/example', '--file',
          os.path.join(project_src_path, build_integration_path, 'Dockerfile'),
          project_src_path
      ])


class GenerateImplTest(fake_filesystem_unittest.TestCase):
  """Tests for _generate_impl."""
  PROJECT_NAME = 'newfakeproject'
  PROJECT_LANGUAGE = 'python'

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    self.setUpPyfakefs()
    self.fs.add_real_directory(helper.OSS_FUZZ_DIR)

  def _verify_templated_files(self, template_dict, directory, language):
    template_args = {
        'project_name': self.PROJECT_NAME,
        'year': 2021,
        'base_builder': helper._base_builder_from_language(language),
        'language': language,
    }
    for filename, template in template_dict.items():
      file_path = os.path.join(directory, filename)
      with open(file_path, 'r') as file_handle:
        contents = file_handle.read()
      self.assertEqual(contents, template % template_args)

  @mock.patch('helper._get_current_datetime',
              return_value=datetime.datetime(year=2021, month=1, day=1))
  def test_generate_oss_fuzz_project(self, _):
    """Tests that the correct files are generated for an OSS-Fuzz project."""
    helper._generate_impl(helper.Project(self.PROJECT_NAME),
                          self.PROJECT_LANGUAGE)
    self._verify_templated_files(
        templates.TEMPLATES,
        os.path.join(helper.OSS_FUZZ_DIR, 'projects', self.PROJECT_NAME),
        self.PROJECT_LANGUAGE)

  def test_generate_external_project(self):
    """Tests that the correct files are generated for a non-OSS-Fuzz project."""
    build_integration_path = '/newfakeproject/build-integration'
    helper._generate_impl(
        helper.Project('/newfakeproject/',
                       is_external=True,
                       build_integration_path=build_integration_path),
        self.PROJECT_LANGUAGE)
    self._verify_templated_files(templates.EXTERNAL_TEMPLATES,
                                 build_integration_path, self.PROJECT_LANGUAGE)

  @mock.patch('helper._get_current_datetime',
              return_value=datetime.datetime(year=2021, month=1, day=1))
  def test_generate_swift_project(self, _):
    """Tests that the swift project uses the correct base image."""
    helper._generate_impl(helper.Project(self.PROJECT_NAME), 'swift')
    self._verify_templated_files(
        templates.TEMPLATES,
        os.path.join(helper.OSS_FUZZ_DIR, 'projects', self.PROJECT_NAME),
        'swift')


class ProjectTest(fake_filesystem_unittest.TestCase):
  """Tests for Project class."""

  def setUp(self):
    self.project_name = 'project'
    self.internal_project = helper.Project(self.project_name)
    self.external_project_path = os.path.join('/path', 'to', self.project_name)
    self.external_project = helper.Project(self.external_project_path,
                                           is_external=True)
    self.setUpPyfakefs()

  def test_init_external_project(self):
    """Tests __init__ method for external projects."""
    self.assertEqual(self.external_project.name, self.project_name)
    self.assertEqual(self.external_project.path, self.external_project_path)
    self.assertEqual(
        self.external_project.build_integration_path,
        os.path.join(self.external_project_path,
                     constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH))

  def test_init_internal_project(self):
    """Tests __init__ method for internal projects."""
    self.assertEqual(self.internal_project.name, self.project_name)
    path = os.path.join(helper.OSS_FUZZ_DIR, 'projects', self.project_name)
    self.assertEqual(self.internal_project.path, path)
    self.assertEqual(self.internal_project.build_integration_path, path)

  def test_dockerfile_path_internal_project(self):
    """Tests that dockerfile_path works as intended."""
    self.assertEqual(
        self.internal_project.dockerfile_path,
        os.path.join(helper.OSS_FUZZ_DIR, 'projects', self.project_name,
                     'Dockerfile'))

  def test_dockerfile_path_external_project(self):
    """Tests that dockerfile_path works as intended."""
    self.assertEqual(
        self.external_project.dockerfile_path,
        os.path.join(self.external_project_path,
                     constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH,
                     'Dockerfile'))

  def test_out(self):
    """Tests that out works as intended."""
    out_dir = self.internal_project.out
    self.assertEqual(
        out_dir,
        os.path.join(helper.OSS_FUZZ_DIR, 'build', 'out', self.project_name))
    self.assertTrue(os.path.exists(out_dir))

  def test_work(self):
    """Tests that work works as intended."""
    work_dir = self.internal_project.work
    self.assertEqual(
        work_dir,
        os.path.join(helper.OSS_FUZZ_DIR, 'build', 'work', self.project_name))
    self.assertTrue(os.path.exists(work_dir))

  def test_corpus(self):
    """Tests that corpus works as intended."""
    corpus_dir = self.internal_project.corpus
    self.assertEqual(
        corpus_dir,
        os.path.join(helper.OSS_FUZZ_DIR, 'build', 'corpus', self.project_name))
    self.assertTrue(os.path.exists(corpus_dir))

  def test_language_internal_project(self):
    """Tests that language works as intended for an internal project."""
    project_yaml_path = os.path.join(self.internal_project.path, 'project.yaml')
    self.fs.create_file(project_yaml_path, contents='language: python')
    self.assertEqual(self.internal_project.language, 'python')

  def test_language_external_project(self):
    """Tests that language works as intended for an external project."""
    self.assertEqual(self.external_project.language, 'c++')
