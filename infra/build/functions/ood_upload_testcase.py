#!/usr/bin/env python3
#
# Copyright 2025 Google LLC
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
"""Upload OSS-Fuzz on Demand testcases."""

import json
import logging
import os
import sys
import subprocess

try:
  import requests
except ImportError:
  print("requests library not found. Installing...")
  subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
  import requests

POST_URL = 'https://oss-fuzz.com/upload-testcase/upload-oauth'


def get_access_token(access_token_path):
  """Returns the ACCESS_TOKEN for upload testcase requests"""
  with open(access_token_path, 'r') as f:
    line = f.readline()
    return line.strip()


def get_headers(access_token_path):
  """Returns the headers required to upload testcase requests"""
  access_token = get_access_token(access_token_path)
  return {
      'Authorization': 'Bearer ' + access_token,
  }


def upload_testcase(upload_url, testcase_path, job, target, access_token_path):
  """Make an upload testcase request."""
  files = {
      'file': open(testcase_path, 'rb'),
  }
  data = {
      'job': job,
      'target': target,
  }
  try:
    resp = requests.post(upload_url,
                         files=files,
                         data=data,
                         headers=get_headers(access_token_path))
    resp.raise_for_status()
    result = json.loads(resp.text)
    print('Upload succeeded. Testcase ID is', result['id'])
  except:
    print('Failed to upload with status', resp.status_code)
    print(resp.text)


def get_file_path(dir_path):
  """Returns the path of a file inside 'dir_path'. Returns None if there are no
  files inside the the given directory."""
  files = []
  for entry in os.scandir(dir_path):
    if entry.is_file():
      return f'{dir_path}/{entry.name}'
  return None


def main():
  """Upload an OSS-Fuzz on Demand testcase."""
  testcase_dir_path = sys.argv[1]
  job = sys.argv[2]
  target = sys.argv[3]
  access_token_path = sys.argv[4]
  testcase_path = get_file_path(testcase_dir_path)

  if not testcase_path:
    print('OSS-Fuzz on Demand did not find any crashes.')
  else:
    upload_testcase(POST_URL, testcase_path, job, target, access_token_path)

  return 0


if __name__ == '__main__':
  main()
