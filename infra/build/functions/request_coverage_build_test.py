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
#
################################################################################
"""Unit tests for Cloud Function request_coverage_build."""
import base64
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb

# pylint: disable=wrong-import-position

import datastore_entities
import request_coverage_build
import test_utils
import yaml

# pylint: disable=no-member


class TestRequestCoverageBuild(unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()
    self.maxDiff = None

  @mock.patch('request_build.run_build', return_value={'id': 'mock-build-id'})
  @mock.patch('build_lib.get_signed_url',
              return_value='https://mocked-signed-url.com')
  def test_get_build_steps_with_base_os_version(self, mock_get_signed_url,
                                                mock_run_build):
    """Test that get_build_steps uses the base_os_version for coverage builds."""
    project_name = 'example'
    base_os_version = 'ubuntu-24-04'

    project_yaml_contents = f"""
homepage: https://my-api.example.com
main_repo: https://github.com/example/my-api
language: c++
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
base_os_version: {base_os_version}
"""
    dockerfile_contents = "FROM gcr.io/oss-fuzz-base/base-builder"

    with mock.patch('request_build.get_project_data') as mock_get_project_data:
      mock_get_project_data.return_value = (
          yaml.safe_load(project_yaml_contents), dockerfile_contents)

      event = {'data': base64.b64encode(project_name.encode('utf-8'))}

      with mock.patch('google.auth.default', return_value=(None, 'oss-fuzz')):
        request_coverage_build.request_coverage_build(event, None)

    self.assertTrue(mock_run_build.called)
    build_steps = mock_run_build.call_args[0][1]

    for inner_list in build_steps:
      for step in inner_list:
        if isinstance(
            step, dict
        ) and 'name' in step and 'gcr.io/oss-fuzz-base/base-runner' in step[
            'name']:
          found_build_check_step = True
          expected_image = f'gcr.io/oss-fuzz-base/base-runner:{base_os_version}'
          self.assertEqual(step['name'], expected_image)
          break
      if found_build_check_step:
        break
    self.assertTrue(found_build_check_step, 'Coverage build step not found.')

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
