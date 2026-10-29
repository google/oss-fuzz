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

import argparse
import datetime
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import constants
import helper
import common_utils
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

  @mock.patch('common_utils.docker_build')
  def test_no_cache(self, mock_docker_build):
    """Tests that cache=False is handled properly."""
    image_name = 'base-image'
    common_utils.build_image_impl(common_utils.Project(image_name), cache=False)
    self.assertIn('--no-cache', mock_docker_build.call_args_list[0][0][0])

  @mock.patch('common_utils.docker_build')
  @mock.patch('common_utils.pull_images')
  def test_pull(self, mock_pull_images, _):
    """Tests that pull=True is handled properly."""
    image_name = 'base-image'
    project = common_utils.Project(image_name, is_external=True)
    self.assertTrue(common_utils.build_image_impl(project, pull=True))
    mock_pull_images.assert_called_with('c++')

  @mock.patch('common_utils.docker_build')
  def test_base_image(self, mock_docker_build):
    """Tests that build_image_impl works as intended with a base-image."""
    image_name = 'base-image'
    self.assertTrue(
        common_utils.build_image_impl(common_utils.Project(image_name)))
    build_dir = os.path.join(common_utils.OSS_FUZZ_DIR,
                             'infra/base-images/base-image')
    mock_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz-base/base-image', '--file',
        os.path.join(build_dir, 'Dockerfile'), build_dir
    ])

  @mock.patch('common_utils.docker_build')
  def test_oss_fuzz_project(self, mock_docker_build):
    """Tests that build_image_impl works as intended with an OSS-Fuzz
    project."""
    project_name = 'example'
    self.assertTrue(
        common_utils.build_image_impl(common_utils.Project(project_name)))
    build_dir = os.path.join(common_utils.OSS_FUZZ_DIR, 'projects',
                             project_name)
    mock_docker_build.assert_called_with([
        '-t', 'gcr.io/oss-fuzz/example', '--file',
        os.path.join(build_dir, 'Dockerfile'), build_dir
    ])

  @mock.patch('common_utils.docker_build')
  def test_external_project(self, mock_docker_build):
    """Tests that build_image_impl works as intended with a non-OSS-Fuzz
    project."""
    with tempfile.TemporaryDirectory() as temp_dir:
      project_src_path = os.path.join(temp_dir, 'example')
      os.mkdir(project_src_path)
      build_integration_path = 'build-integration'
      project = common_utils.Project(
          project_src_path,
          is_external=True,
          build_integration_path=build_integration_path)
      self.assertTrue(common_utils.build_image_impl(project))
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


class _SyncPool:  # pylint: disable=too-few-public-methods
  """Synchronous pool double that maps over all items without
  short-circuiting."""

  def map(self, func, iterable):
    """Synchronously maps func over iterable."""
    return list(map(func, iterable))


class DownloadCorporaTest(unittest.TestCase):
  """Tests for download_corpora failure propagation and compatibility."""

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.original_cwd = os.getcwd()
    os.chdir(self.temp_dir.name)

  def tearDown(self):
    os.chdir(self.original_cwd)
    self.temp_dir.cleanup()

  def _make_args(self, fuzz_targets, public=True):

    class DummyProject:  # pylint: disable=too-few-public-methods
      """Dummy project for testing."""
      name = 'test-project'
      corpus = os.path.join(self.temp_dir.name, 'corpus')

    return argparse.Namespace(
        project=DummyProject(),
        public=public,
        fuzz_target=fuzz_targets,
    )

  def _target_zip(self, project_name, fuzzer):
    target_corpus_dir = f'build/corpus/{project_name}'
    return os.path.join(target_corpus_dir, fuzzer + '.zip')

  def _target_fuzzer_dir(self, project_name, fuzzer):
    target_corpus_dir = f'build/corpus/{project_name}'
    return os.path.join(target_corpus_dir, fuzzer)

  @mock.patch('helper.logger.error')
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_public_missing_unzip_fails(self, mock_check_call, _, __,
                                      mock_logger_error):
    """Tests that missing unzip executable fails operation and skips cleanup."""
    args = self._make_args(['fuzzer1'], public=True)
    target_zip = self._target_zip(args.project.name, 'fuzzer1')

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        with open(target_zip, 'wb') as f:
          f.write(b'dummy-zip-data')
        return 0
      if cmd[0] == 'unzip':
        raise FileNotFoundError("No such file or directory: 'unzip'")
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertFalse(result)
    self.assertEqual(helper.bool_to_retcode(result), 1)
    # Target failure is logged
    self.assertTrue(
        any('fuzzer1' in str(call)
            for call in mock_logger_error.call_args_list))
    # Success-path archive removal is not reached
    self.assertTrue(os.path.exists(target_zip))

  @mock.patch('helper.logger.error')
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_public_download_oserror_fails(self, mock_check_call, _, __,
                                         mock_logger_error):
    """Tests that OSError during download fails operation and skips
    extraction."""
    args = self._make_args(['fuzzer1'], public=True)
    target_zip = self._target_zip(args.project.name, 'fuzzer1')

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        raise OSError('Download execution failed')
      if cmd[0] == 'unzip':
        return 0
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertFalse(result)
    self.assertEqual(helper.bool_to_retcode(result), 1)
    # Extraction is never attempted
    self.assertFalse(
        any(call[0][0][0] == 'unzip'
            for call in mock_check_call.call_args_list))
    # Archive file does not exist / cleanup not reached
    self.assertFalse(os.path.exists(target_zip))
    # Target failure is logged
    self.assertTrue(
        any('fuzzer1' in str(call)
            for call in mock_logger_error.call_args_list))

  @mock.patch('helper.logger.error')
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_public_download_nonzero_exit_fails(self, mock_check_call, _, __,
                                              mock_logger_error):
    """Tests that nonzero download exit code fails operation and skips
    extraction."""
    args = self._make_args(['fuzzer1'], public=True)

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        raise subprocess.CalledProcessError(1, cmd)
      if cmd[0] == 'unzip':
        return 0
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertFalse(result)
    self.assertEqual(helper.bool_to_retcode(result), 1)
    # Extraction is not attempted
    self.assertFalse(
        any(call[0][0][0] == 'unzip'
            for call in mock_check_call.call_args_list))
    # Failure reporting logged target
    self.assertTrue(
        any('fuzzer1' in str(call)
            for call in mock_logger_error.call_args_list))

  @mock.patch('helper.logger.error')
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_public_extraction_nonzero_exit_fails(self, mock_check_call, _, __,
                                                mock_logger_error):
    """Tests that nonzero extraction exit code fails operation without archive
    removal."""
    del mock_logger_error
    args = self._make_args(['fuzzer1'], public=True)
    target_zip = self._target_zip(args.project.name, 'fuzzer1')

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        with open(target_zip, 'wb') as f:
          f.write(b'dummy-zip-data')
        return 0
      if cmd[0] == 'unzip':
        raise subprocess.CalledProcessError(1, cmd)
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertFalse(result)
    self.assertEqual(helper.bool_to_retcode(result), 1)
    # Success-path archive removal is not reached
    self.assertTrue(os.path.exists(target_zip))

  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_public_success(self, mock_check_call, _, __):
    """Tests that successful download and extraction returns True and cleans
    archive."""
    args = self._make_args(['fuzzer1'], public=True)
    target_zip = self._target_zip(args.project.name, 'fuzzer1')
    expected_dest = self._target_fuzzer_dir(args.project.name, 'fuzzer1')

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        with open(target_zip, 'wb') as f:
          f.write(b'dummy-zip-data')
        return 0
      if cmd[0] == 'unzip':
        return 0
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertTrue(result)
    self.assertEqual(helper.bool_to_retcode(result), 0)
    # Extraction invoked with expected archive and destination
    mock_check_call.assert_any_call(
        ['unzip', '-q', '-o', target_zip, '-d', expected_dest], stdout=mock.ANY)
    # Success-path archive removal occurs
    self.assertFalse(os.path.exists(target_zip))

  @mock.patch('helper.logger.error')
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_mixed_target_results(self, mock_check_call, _, __,
                                mock_logger_error):
    """Tests that if any target fails, aggregate is False and all targets are
    processed."""
    args = self._make_args(['target1', 'target2'], public=True)
    processed_targets = []

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['wget', '--version']:
        return 0
      if cmd[0] == 'wget':
        zip_path = cmd[3]
        if 'target1' in zip_path:
          processed_targets.append('target1')
          with open(zip_path, 'wb') as f:
            f.write(b'data1')
          return 0
        if 'target2' in zip_path:
          processed_targets.append('target2')
          raise OSError('Download failed for target2')
      if cmd[0] == 'unzip':
        return 0
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertFalse(result)
    self.assertEqual(helper.bool_to_retcode(result), 1)
    # Both targets were processed
    self.assertEqual(set(processed_targets), {'target1', 'target2'})
    # Target failure is logged for target2
    self.assertTrue(
        any('target2' in str(call)
            for call in mock_logger_error.call_args_list))

  @mock.patch('helper._get_latest_corpus', return_value=None)
  @mock.patch('helper.ThreadPool', side_effect=_SyncPool)
  @mock.patch('helper.common_utils.check_project_exists', return_value=True)
  @mock.patch('helper.subprocess.check_call')
  def test_private_path_compatibility(self, mock_check_call, _, __,
                                      mock_get_latest_corpus):
    """Tests that private download returning None without raising is treated
    as success."""
    args = self._make_args(['fuzzer1'], public=False)

    def check_call_side_effect(cmd, stdout=None):
      del stdout
      if cmd[:2] == ['gsutil', '--version']:
        return 0
      raise AssertionError(f'Unexpected command: {cmd}')

    mock_check_call.side_effect = check_call_side_effect

    result = helper.download_corpora(args)

    self.assertTrue(result)
    self.assertEqual(helper.bool_to_retcode(result), 0)
    mock_get_latest_corpus.assert_called_once()
