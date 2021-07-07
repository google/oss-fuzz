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
import unittest

from filestore.github_actions import github_api
import test_helpers


class GetHttpAuthHeaders(unittest.TestCase):
  """Tests for get_http_auth_headers."""

  def test_get_http_auth_headers(self):
    """Tests that get_http_auth_headers returns the correct result."""
    github_token = 'example githubtoken'
    run_config = test_helpers.create_run_config(github_token=github_token)
    expected_headers = {
        'Authorization': 'token {token}'.format(token=github_token),
        'Accept': 'application/vnd.github.v3+json',
    }
    self.assertEqual(expected_headers,
                     github_api.get_http_auth_headers(run_config))
