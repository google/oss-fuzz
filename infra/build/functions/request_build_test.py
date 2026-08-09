# Copyright 2020 Google Inc.
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
"""Unit tests for Cloud Function request builds which builds projects."""
import base64
import json
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb

# pylint: disable=wrong-import-position

import datastore_entities
import request_build
import test_utils
import build_project
import build_lib

# pylint: disable=no-member


class TestRequestBuilds(unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.mock_get_signed_url = mock.patch(
        'build_lib.get_signed_url',
        return_value='https://example.com/signed-url').start()
    self.mock_get_signed_policy = mock.patch(
        'build_lib.get_signed_policy_document_upload_prefix',
        return_value=mock.MagicMock()).start()
    self.mock_curl_args = mock.patch(
        'build_lib.signed_policy_document_curl_args', return_value=[]).start()

  def tearDown(self):
    mock.patch.stopall()

  def test_get_build_steps_no_project(self):
    """Test for when project isn't available in datastore."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_build_steps,
                        'test-project')

  @mock.patch('build_project.run_build', return_value={'id': 'mock-build-id'})
  def test_get_build_steps_with_base_os_version(self, mock_run_build):
    """Test that get_build_steps uses the base_os_version."""
    project_name = 'example'
    base_os_version = 'ubuntu-24-04'

    project_yaml_contents = """
homepage: https://my-api.example.com
main_repo: https://github.com/example/my-api
language: c++
vendor_ccs: []
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
base_os_version: ubuntu-24-04
"""
    dockerfile_contents = """
# Copyright 2017 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make

# Get *your* source code here.
RUN git clone https://github.com/google/oss-fuzz.git my-git-repo
WORKDIR my-git-repo
COPY build.sh $SRC/
"""
    with ndb.Client().context():
      datastore_entities.Project(name=project_name,
                                 project_yaml_contents=project_yaml_contents,
                                 dockerfile_contents=dockerfile_contents).put()

    event = {'data': base64.b64encode(project_name.encode('utf-8'))}

    with mock.patch('google.auth.default', return_value=(None, 'oss-fuzz')):
      request_build.request_build(event, None)

    self.assertTrue(mock_run_build.called)

    self.assertEqual(2, mock_run_build.call_count)
    build_steps = mock_run_build.call_args_list[0][0][1]

    found_build_check_step = False
    for inner_step in build_steps[0]:
      if isinstance(
          inner_step,
          dict) and inner_step.get('id') and 'build-check' in inner_step['id']:
        found_build_check_step = True
        expected_image = f'gcr.io/oss-fuzz-base/base-runner:{base_os_version}'
        self.assertIn(expected_image, inner_step['args'])
        break
    self.assertTrue(found_build_check_step, 'Build check step not found.')

  def test_build_history(self):
    """Testing build history."""
    with ndb.Client().context():
      datastore_entities.BuildsHistory(id='test-project-fuzzing',
                                       build_tag='fuzzing',
                                       project='test-project',
                                       build_ids=[str(i) for i in range(1, 65)
                                                 ]).put()
      request_build.update_build_history('test-project', '65', 'fuzzing')
      expected_build_ids = [str(i) for i in range(2, 66)]

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_build_history_no_existing_project(self):
    """Testing build history when build history object is missing."""
    with ndb.Client().context():
      request_build.update_build_history('test-project', '1', 'fuzzing')
      expected_build_ids = ['1']

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_get_project_data(self):
    """Testing get project data."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_project_data,
                        'test-project')

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
