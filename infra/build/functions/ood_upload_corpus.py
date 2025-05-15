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
try:
  import requests
except ImportError:
  print("requests library not found. Installing...")
  subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
  import requests

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


def upload_corpus(output_corpus_directory, serialized_doc_str, path_prefix, num_uploads):
  """."""
  retrieved_bytes = base64.b64decode(serialized_doc_str.encode('utf-8'))
  doc = pickle.loads(retrieved_bytes)
  file_paths = get_files_path(output_corpus_directory, num_uploads)
  for file_path in file_paths:
    suffix = uuid.uuid4().hex
    upload_path = path_prefix + suffix
    upload_corpus_file(file_path, upload_path, doc)


def main():
  """ ."""
  install_requirements()
  output_corpus_directory = sys.argv[1]
  serialized_doc_str = sys.argv[2]
  path_prefix = sys.argv[3]
  num_uploads = int(sys.argv[4])
  upload_corpus(output_corpus_directory, serialized_doc_str, path_prefix, num_uploads)


if __name__ == '__main__':
  sys.exit(main())
