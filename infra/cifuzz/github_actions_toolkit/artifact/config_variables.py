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
"""Module for getting configuration values (often from env). Based on
config-variables.ts."""

import os

UPLOAD_CHUNK_SIZE = 8 * 1024**2  # 8 MB.
UPLOAD_FILE_CONCURRENCY = 2


def get_runtime_url():
  """Returns the value of the ACTIONS_RUNTIME_URL var in the environment. Raises
  an exception if not set."""
  url = os.environ.get('ACTIONS_RUNTIME_URL')
  if not url:
    raise Exception('Unable to get ACTIONS_RUNTIME_URL env variable')
  return url


def get_runtime_token():
  """Returns the value of the ACTIONS_RUNTIME_TOKEN var in the environment.
  Raises an exception if not set."""
  token = os.environ.get('ACTIONS_RUNTIME_TOKEN')
  if not token:
    raise Exception('Unable to get ACTIONS_RUNTIME_TOKEN env variable')
  return token


def get_work_flow_run_id():
  """Returns the value of the GITHUB_RUN_ID var in the environment. Raises an
  exception if not set."""
  work_flow_run_id = os.environ.get('GITHUB_RUN_ID')
  if not work_flow_run_id:
    raise Exception('Unable to get GITHUB_RUN_ID env variable.')
  return work_flow_run_id


def get_retention_days():
  """Returns the value of the GITHUB_RETENTION_DAYS or None if it wasn't
  specified."""
  return os.environ.get('GITHUB_RETENTION_DAYS')
