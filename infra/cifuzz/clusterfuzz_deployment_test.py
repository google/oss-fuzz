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
"""Tests for clusterfuzz_deployment.py"""

import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import clusterfuzz_deployment
import test_helpers

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# An example fuzzer that triggers an error.
EXAMPLE_FUZZER = 'example_crash_fuzzer'


def _create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  defaults = {'is_github': True, 'project_name': EXAMPLE_PROJECT}
  for default_key, default_value in defaults.items():
    if default_key not in kwargs:
      kwargs[default_key] = default_value

  return test_helpers.create_run_config(**kwargs)


def _create_deployment(**kwargs):
  config = _create_config(**kwargs)
  return clusterfuzz_deployment.get_clusterfuzz_deployment(config)


class OSSFuzzTest(fake_filesystem_unittest.TestCase):
  """Tests OSSFuzz."""

  OUT_DIR = '/out'

  def setUp(self):
    self.setUpPyfakefs()
    self.deployment = _create_deployment()

  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_corpus(self, mocked_download_and_unpack_zip):
    """Tests that we can download a corpus for a valid project."""
    result = self.deployment.download_corpus(EXAMPLE_FUZZER, self.OUT_DIR)
    self.assertIsNotNone(result)
    expected_corpus_dir = os.path.join(self.OUT_DIR, 'cifuzz-corpus',
                                       EXAMPLE_FUZZER)
    expected_url = ('https://storage.googleapis.com/example-backup.'
                    'clusterfuzz-external.appspot.com/corpus/libFuzzer/'
                    'example_crash_fuzzer/public.zip')
    call_args, _ = mocked_download_and_unpack_zip.call_args
    self.assertEqual(call_args, (expected_url, expected_corpus_dir))

  @mock.patch('http_utils.download_and_unpack_zip', return_value=False)
  def test_download_fail(self, _):
    """Tests that when downloading fails, None is returned."""
    corpus_path = self.deployment.download_corpus(EXAMPLE_FUZZER, self.OUT_DIR)
    self.assertIsNone(corpus_path)

  def test_get_latest_build_name(self):
    """Tests that the latest build name can be retrieved from GCS."""
    latest_build_name = self.deployment.get_latest_build_name()
    self.assertTrue(latest_build_name.endswith('.zip'))
    self.assertTrue('address' in latest_build_name)


if __name__ == '__main__':
  unittest.main()
