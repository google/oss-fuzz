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
    logging.info("requests library not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests
 
# Note: your @google.com account needs to be added to
# https://team.git.corp.google.com/gosst/clusterfuzz-config/+/refs/heads/master/configs/internal/gae/auth.yaml#25
# under "whitelisted_oauth_emails".

GET_URL = 'https://oss-fuzz.com/upload-testcase/get-url-oauth'
# GET_URL = 'https://staging3-dot-cluster-fuzz.appspot.com/upload-testcase/get-url-oauth'
# ACCESS_TOKEN: gcloud auth print-access-token

def get_access_token():
  """Returns the ACCESS_TOKEN for upload testcase requests"""
  try:
      import google.auth
  except ImportError:
      logging.info("google-auth library not found. Installing...")
      subprocess.check_call([sys.executable, "-m", "pip", "install", "google-auth"])
      import google.auth

  # credentials, project = google.auth.default() #acho que não precisa disso
  command = ['gcloud auth print-access-token']
  result = subprocess.run(
              command,
              capture_output=True,
              text=True,
              check=True,
              shell=True
          )
  # Remove the las character "\n"
  return result.stdout[:-1]

def get_headers():
  """Returns the headers required to upload testcase requests"""
  access_token = get_access_token()
  return {
      'Authorization': 'Bearer ' + access_token,
  }


# def upload(upload_url, testcase_path, job, target):
#   files = {
#       'file': open(testcase_path),
#   }

#   data = {
#       'job': job,
#       'target': target,
#   }
#   resp = requests.post(upload_url, files=files, data=data,
#                        headers=get_headers())
#   if resp.status_code == 200:
#     result = json.loads(resp.text)
#     print('Upload succeeded. Testcase ID is', result['id'])
#   else:
#     print('Failed to upload with status', resp.status_code)
#     print(resp.text)


def get_file_path(dir_path):
  """Returns the path of a file inside 'dir_path'. Returns None if there are no
  files inside the the given directory."""
  files = []
  for entry in os.scandir(dir_path):
    if entry.is_file():
      return entry.name
  return None


def main():
  testcase_dir_path = sys.argv[1]
  job = sys.argv[2]
  target = sys.argv[3]
  testcase_path = get_file_path(testcase_dir_path)

  if not testcase_path:
    logging.info('OSS-Fuzz on Demand did not find any crashes.')
  else:
    resp = requests.post(GET_URL, headers=get_headers()).text
    logging.info(resp)
    result = json.loads(resp)
    upload_url = result['uploadUrl']
    logging.info('upload url is', upload_url)
  
    # upload(upload_url, testcase_path, job, target)
  
  return 0


if __name__ == '__main__':
  main()
