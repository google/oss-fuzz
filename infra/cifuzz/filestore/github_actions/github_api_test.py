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
"""Tests for github_api."""
import os
import sys
import unittest

# pylint: disable=wrong-import-position,import-error
sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir,
                     os.path.pardir)))

from filestore.github_actions import github_api
import test_helpers


class GetHttpAuthHeaders(unittest.TestCase):
  """Tests for get_http_auth_headers."""

  def test_get_http_auth_headers(self):
    """Tests that get_http_auth_headers returns the correct result."""
    test_helpers.patch_environ(self)
    os.environ['ACTIONS_RUNTIME_TOKEN'] = 'githubtoken'
    expected_headers = {
        'Authorization': 'Bearer githubtoken',
    }
    self.assertEqual(expected_headers, github_api.get_http_auth_headers())
