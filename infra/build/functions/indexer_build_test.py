# Copyright 2026 Google LLC
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
"""Unittests for indexer build steps."""
import sys
import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

FUNCTIONS_DIR = os.path.dirname(__file__)
sys.path.append(FUNCTIONS_DIR)

import build_project
import build_lib


class TestIndexerBuildSteps(fake_filesystem_unittest.TestCase):
  """Unittests for indexer build."""

  def setUp(self):
    self.setUpPyfakefs()

  @mock.patch('build_lib.get_signed_policy_document_upload_prefix')
  @mock.patch('build_lib.signed_policy_document_curl_args')
  @mock.patch('build_lib.upload_using_signed_policy_document')
  @mock.patch('build_lib.get_project_image_steps')
  def test_get_indexer_build_steps(self, mock_get_project_image_steps,
                                   mock_upload_using_policy,
                                   mock_signed_policy_args,
                                   mock_get_policy_doc):
    """Test get_indexer_build_steps."""
    mock_get_project_image_steps.return_value = []
    mock_policy_doc = mock.Mock()
    mock_policy_doc.bucket = 'test-bucket'
    mock_get_policy_doc.return_value = mock_policy_doc
    mock_signed_policy_args.return_value = ['-F', 'policy=foo']
    mock_upload_using_policy.return_value = {'name': 'upload_srcmap'}
    project_name = 'test-project'
    project_yaml = {
        'language': 'c++',
        'sanitizers': ['address'],
        'architectures': ['x86_64'],
        'main_repo': 'https://github.com/test/repo.git',
        'indexer': {
            'targets': ['target1']
        }
    }
    dockerfile = '''FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get install -y make'''

    config = build_project.Config(upload=True, experiment=False)
    steps, reason = build_project.get_indexer_build_steps(
        project_name, project_yaml, dockerfile, config)
    indexer_step = None
    for step in steps:
      if 'args' in step and ('--name' in step['args'] and
                             'indexed-container' in step['args']):
        indexer_step = step
        break

    self.assertIsNotNone(indexer_step, "Indexer build step not found")
    bash_command = indexer_step['args'][-1]
    self.assertIn('unshallow_repos.py', bash_command)

    upload_step = None
    for step in steps:
      if 'args' in step and len(step['args']) >= 2 and isinstance(
          step['args'][1], str) and 'for tar in' in step['args'][1]:
        upload_step = step
        break

    self.assertIsNotNone(upload_step, "Upload step not found")
    upload_command = upload_step['args'][1]
    self.assertIn('for tar in /workspace/out/none-address-x86_64/*.tar',
                  upload_command)
    self.assertIn('curl -F policy=foo', upload_command)


if __name__ == '__main__':
  unittest.main()
