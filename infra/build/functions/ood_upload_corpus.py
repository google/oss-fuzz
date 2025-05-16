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
"""."""
import base64
import logging
import os
import pickle
import subprocess
import sys
import uuid

import build_lib

def upload_corpus_file(file_path, upload_path, doc):
  """."""
  url = f'https://{doc.bucket}.storage.googleapis.com'
  url = f'https://storage.googleapis.com/{doc.bucket}'
  print(f'Upload url: {url}')
  data = {
      'key': upload_path,
      'policy': doc.policy,
      'x-goog-algorithm': doc.x_goog_algorithm,
      'x-goog-date': doc.x_goog_date,
      'x-goog-credential': doc.x_goog_credential,
      'x-goog-signature': doc.x_goog_signature,
  }
  files = {
      'file': open(file_path, 'rb'),
  }
  print('Request files:')
  for key in files:
    if key != 'policy' and key != 'x-goog-signature':
      print(f'{key}: {files[key]}')
  try:
    response = requests.post(url, data=data, files=files)
    response.raise_for_status()
    print(f"File uploaded successfully to {url}/{upload_path}")
  except requests.exceptions.RequestException as e:
    print(f"Error uploading file: {e}")
    if response is not None:
      print(f"Response status code: {response.status_code}")
      print(f"Response text: {response.text}")


def get_files_path(directory_path, num_files):
  """."""
  file_paths = []
  for root, _, files in os.walk(directory_path):
    for name in files:
      file_path = os.path.join(root, name)
      file_paths.append(file_path)
      if len(file_paths) >= num_files:
        return file_paths
  return file_paths


def upload_corpus(output_corpus_directory, doc_str, path_prefix, num_uploads):
  """."""
  doc_data = json.loads(doc_str)
  doc = build_lib.SignedPolicyDocument(**doc_data)
  file_paths = get_files_path(output_corpus_directory, num_uploads)
  for file_path in file_paths:
    suffix = uuid.uuid4().hex
    upload_path = path_prefix + suffix
    upload_corpus_file(file_path, upload_path, doc)


def main():
  """ ."""
  output_corpus_directory = sys.argv[1]
  doc_str = sys.argv[2]
  path_prefix = sys.argv[3]
  num_uploads = int(sys.argv[4])
  upload_corpus(output_corpus_directory, doc_str, path_prefix, num_uploads)


if __name__ == '__main__':
  sys.exit(main())
