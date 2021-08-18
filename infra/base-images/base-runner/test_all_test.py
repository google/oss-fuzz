# Copyright 2020 Google LLC
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
"""Tests test_all.py"""
import unittest
from unittest import mock

import test_all


class TestTestAll(unittest.TestCase):
  """Tests for the test_all_function."""

  @mock.patch('test_all.find_fuzz_targets', return_value=[])
  @mock.patch('builtins.print')
  def test_test_all_no_fuzz_targets(self, mock_print, _):
    """Tests that test_all returns False when there are no fuzz targets."""
    outdir = '/out'
    allowed_broken_targets_percentage = 0
    self.assertFalse(
        test_all.test_all(outdir, allowed_broken_targets_percentage))
    mock_print.assert_called_with('ERROR: No fuzz targets found.')


if __name__ == '__main__':
  unittest.main()
