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
import base64
import logging
import os
import pickle
import subprocess
import sys
import uuid
# import requests

def execute_shell_command(command_args, check_return_code=True):
  """ """
  result = subprocess.run(
      command_args,
      check=check_return_code,
      capture_output=True,
      text=True
  )

  if result.stdout:
      print("   STDOUT:")
      print(result.stdout.strip())
  if result.stderr:
      print("   STDERR:")
      print(result.stderr.strip())


def install_requirements():
  cmd1 = [
      'python',
      '-m',
      'pip',
      'install',
      '--upgrade',
      'pip'
  ]
  requirements_file = '/workspace/oss-fuzz/infra/build/functions/requirements.txt'
  cmd2 = [
      'pip',
      'install',
      '-r',
      requirements_file
  ]

  execute_shell_command(cmd1)
  execute_shell_command(cmd2)


def upload_corpus_file(file_path, suffix, doc):
  """."""
  url = f'https://{doc.bucket}.storage.googleapis.com'
  upload_path = doc.path_prefix + suffix
  files = {
      'key': (None, upload_path),
      'file': (file_path.split('/')[-1], open(file_path, 'rb')),
      'policy': (None, doc.policy),
      'x-goog-algorithm': (None, doc.x_goog_algorithm),
      'x-goog-date': (None, doc.x_goog_date),
      'x-goog-credential': (None, doc.x_goog_credential),
      'x-goog-signature': (None, doc.x_goog_signature),
  }
  logging.info(f'Corpus request files:\n{files}')
  print(f'Corpus request files:\n{files}')
  # try:
  #   response = requests.post(url, files=files)
  #   response.raise_for_status()
  #   logging.info(f"File uploaded successfully to {url}/{upload_path}")
  # except requests.exceptions.RequestException as e:
  #   logging.info(f"Error uploading file: {e}")
  #   if response is not None:
  #     logging.info(f"Response status code: {response.status_code}")
  #     logging.info(f"Response text: {response.text}")


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


def upload_corpus(output_corpus_directory, serialized_doc_str, num_uploads):
  """."""
  retrieved_bytes = base64.b64decode(serialized_doc_str.encode('utf-8'))
  doc = pickle.loads(retrieved_bytes)
  file_paths = get_files_path(output_corpus_directory, num_uploads)
  logging.info(f'Files paths:\n{file_paths}')
  for file_path in file_paths:
    suffix = uuid.uuid4().hex
    upload_corpus_file(file_path, suffix, doc)


def main():
  """ ."""
  install_requirements()
  output_corpus_directory = sys.argv[1]
  serialized_doc_str = sys.argv[2]
  num_uploads = int(sys.argv[3])
  upload_corpus(output_corpus_directory, serialized_doc_str, num_uploads)


if __name__ == '__main__':
  sys.exit(main())
