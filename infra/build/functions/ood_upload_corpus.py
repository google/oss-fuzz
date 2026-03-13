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
"""Upload OSS-Fuzz on Demand output corpus to GCS."""

import argparse
import base64
import json
import logging
import os
import pickle
import requests
import subprocess
import sys
import uuid

import build_lib


def get_corpus_signed_policy_document(project_name, fuzz_target_name):
  """Returns a signed policy document and a path prefix to upload corpus to GCS."""
  bucket = f'{project_name}-corpus.clusterfuzz-external.appspot.com'
  path_prefix = f'libFuzzer/{fuzz_target_name}/'
  signed_policy_document = build_lib.get_signed_policy_document_upload_prefix(
      bucket, path_prefix)
  return signed_policy_document, path_prefix


def upload_corpus_file(file_path, upload_path, doc):
  """Make a request to upload a corpus file to GCS."""
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
  try:
    response = requests.post(url, data=data, files=files)
    response.raise_for_status()
    print(f'File uploaded successfully to {url}/{upload_path}')
  except requests.exceptions.RequestException as e:
    print(f'Error uploading file: {e}')
    if response is not None:
      print(f'Response status code: {response.status_code}')
      print(f'Response text: {response.text}')


def get_files_path(directory_path, num_files):
  """Returns the path for |num_files| corpus files."""
  file_paths = []
  for root, _, files in os.walk(directory_path):
    for name in files:
      file_path = os.path.join(root, name)
      file_paths.append(file_path)
      if len(file_paths) >= num_files:
        return file_paths
  return file_paths


def upload_corpus(doc_str, path_prefix, output_corpus_directory, num_uploads):
  """Uploads |num_uploads| corpus files using |doc_str| signed document policy.
  It uses |path_prefix| to get the upload path."""
  doc_data = json.loads(doc_str)
  doc = build_lib.SignedPolicyDocument(**doc_data)
  file_paths = get_files_path(output_corpus_directory, num_uploads)
  for file_path in file_paths:
    suffix = uuid.uuid4().hex
    upload_path = path_prefix + suffix
    upload_corpus_file(file_path, upload_path, doc)


def get_args():
  """Parses command line arguments and returns them."""
  parser = argparse.ArgumentParser(
      description="Script to upload corpus elements to GCS.")
  parser.add_argument("doc_str",
                      type=str,
                      help="The signed document policy string.")
  parser.add_argument("path_prefix",
                      type=str,
                      help="The prefix to get the corpus upload path.")
  parser.add_argument(
      "output_corpus_directory",
      type=str,
      help="The directory where the fuzzing output corpus is stored.")
  parser.add_argument("num_uploads",
                      type=int,
                      help="The number of elements which will be uploaded.")
  args = parser.parse_args()
  return args


def main():
  """Upload OSS-Fuzz on Demand output corpus to GCS."""
  args = get_args()
  upload_corpus(args.doc_str, args.path_prefix, args.output_corpus_directory,
                args.num_uploads)


if __name__ == '__main__':
  sys.exit(main())
