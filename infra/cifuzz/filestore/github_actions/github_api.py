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
"""Module for dealing with the GitHub API. This is different from
github_actions_toolkit which only deals with the actions API. We need to use
both."""
import logging
import os
import sys

import requests

import filestore

# pylint: disable=wrong-import-position,import-error

sys.path.append(
    os.path.join(__file__, os.path.pardir, os.path.pardir, os.path.pardir,
                 os.path.pardir))
import retry

_MAX_ITEMS_PER_PAGE = 100

_GET_ATTEMPTS = 3
_GET_BACKOFF = 1


def get_http_auth_headers(config):
  """Returns HTTP headers for authentication to the API."""
  authorization = f'token {config.token}'
  return {
      'Authorization': authorization,
      'Accept': 'application/vnd.github.v3+json'
  }


def _get_artifacts_list_api_url(repo_owner, repo_name):
  """Returns the artifacts_api_url for |repo_name| owned by |repo_owner|."""
  return (f'https://api.github.com/repos/{repo_owner}/'
          f'{repo_name}/actions/artifacts')


@retry.wrap(_GET_ATTEMPTS, _GET_BACKOFF)
def _do_get_request(*args, **kwargs):
  """Wrapped version of requests.get that does retries."""
  return requests.get(*args, **kwargs)


def _get_items(url, headers):
  """Generator that gets and yields items from a GitHub API endpoint (specified
  by |URL|) sending |headers| with the get request."""
  # Github API response pages are 1-indexed.
  page_counter = 1

  # Set to infinity so we run loop at least once.
  total_num_items = float('inf')

  item_num = 0
  while item_num < total_num_items:
    params = {'per_page': _MAX_ITEMS_PER_PAGE, 'page': str(page_counter)}
    response = _do_get_request(url, params=params, headers=headers)
    response_json = response.json()
    if not response.status_code == 200:
      # Check that request was successful.
      logging.error('Request to %s failed. Code: %d. Response: %s',
                    response.request.url, response.status_code, response_json)
      raise filestore.FilestoreError('Github API request failed.')

    if total_num_items == float('inf'):
      # Set proper total_num_items
      total_num_items = response_json['total_count']

    # Get the key for the items we are after.
    keys = [key for key in response_json.keys() if key != 'total_count']
    assert len(keys) == 1, keys
    items_key = keys[0]

    for item in response_json[items_key]:
      yield item
      item_num += 1

    page_counter += 1


def find_artifact(artifact_name, artifacts):
  """Find the artifact with the name |artifact_name| in |artifacts|."""
  for artifact in artifacts:
    # TODO(metzman): Handle multiple by making sure we download the latest.
    if artifact['name'] == artifact_name and not artifact['expired']:
      return artifact
  return None


def list_artifacts(owner, repo, headers):
  """Returns a generator of all the artifacts for |owner|/|repo|."""
  url = _get_artifacts_list_api_url(owner, repo)
  logging.debug('Getting artifacts from: %s', url)
  return _get_items(url, headers)
