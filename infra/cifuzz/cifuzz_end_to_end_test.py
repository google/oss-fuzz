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
"""End-to-End tests for CIFuzz."""
import os
import unittest

import run_cifuzz
import test_helpers

CIFUZZ_DIR = os.path.dirname(os.path.abspath(__file__))
EXTERNAL_PROJECT_PATH = os.path.join(CIFUZZ_DIR, 'test_data',
                                     'external-project')


# This test will fail if not run as root because the fuzzer build process
# creates binaries that only root can write to.
# Use a seperate env var to keep this seperate from integration tests which
# don't have this annoying property.
@unittest.skipIf(not os.getenv('END_TO_END_TESTS'),
                 'END_TO_END_TESTS=1 not set')
class EndToEndTest(unittest.TestCase):
  """End-to-End tests for CIFuzz."""

  def setUp(self):
    test_helpers.patch_environ(self, runner=True)

  def test_simple(self):
    """Simple end-to-end test using run_cifuzz.main()."""
    os.environ['REPOSITORY'] = 'external-project'
    os.environ['PROJECT_SRC_PATH'] = EXTERNAL_PROJECT_PATH
    os.environ['FILESTORE'] = 'no_filestore'
    os.environ['NO_CLUSTERFUZZ_DEPLOYMENT'] = 'True'

    with test_helpers.docker_temp_dir() as temp_dir:
      os.environ['WORKSPACE'] = temp_dir
      # TODO(metzman): Verify the crash, affected fuzzers, and other things.
      self.assertEqual(run_cifuzz.main(), 1)
