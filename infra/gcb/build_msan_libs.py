# Copyright 2020 Google Inc.
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
#!/usr/bin/python2
"""Build base images on Google Cloud Builder.

Usage: build_base_images.py
"""
from __future__ import print_function

import datetime
import os
import sys
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

import build_base_images


def get_steps(image):
  """Get build steps for msan-libs-builder."""

  timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M')
  upload_name = 'msan-libs-' + timestamp + '.zip'

  steps = build_base_images.get_steps([
      'base-sanitizer-libs-builder',
      'msan-libs-builder',
  ])

  steps.extend([{
      'name': image,
      'args': [
          'bash',
          '-c',
          'cd /msan && zip -r /workspace/libs.zip .',
      ],
  }, {
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          'cp',
          '/workspace/libs.zip',
          'gs://oss-fuzz-msan-libs/' + upload_name,
      ],
  }])

  return steps


# pylint: disable=no-member
def main():
  """Build msan libs."""
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  image = 'gcr.io/oss-fuzz-base/msan-libs-builder'
  steps = get_steps(image)
  build_body = {
      'steps': steps,
      'timeout': str(6 * 3600) + 's',
      'options': options,
      'images': [
          'gcr.io/oss-fuzz-base/base-sanitizer-libs-builder',
          image,
      ],
  }
  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(projectId='oss-fuzz-base',
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print('Logs:', build_base_images.get_logs_url(build_id), file=sys.stderr)
  print(build_id)


if __name__ == '__main__':
  main()
