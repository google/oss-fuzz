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

import unittest
from unittest import mock

import helper


class TestShell(unittest.TestCase):
  """Tests 'shell' command."""

  @mock.patch('helper.docker_run')
  @mock.patch('helper.build_image_impl')
  def test_base_runner_debug(self, mocked_build_image_impl, _):
    """Tests that shell base-runner-debug works as intended."""
    image_name = 'base-runner-debug'
    unparsed_args = ['shell', image_name]
    args = helper.parse_args(unparsed_args)
    args.sanitizer = 'address'
    result = helper.shell(args)
    mocked_build_image_impl.assert_called_with(image_name)
    self.assertEqual(result, 0)
