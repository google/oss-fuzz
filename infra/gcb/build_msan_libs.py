#!/usr/bin/python2
"""Build base images on Google Cloud Builder.

Usage: build_base_images.py
"""

import datetime
import os
import yaml
import sys

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

import build_base_images


def main():
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  image = 'gcr.io/oss-fuzz-base/msan-builder'
  steps = build_base_images.get_steps(['base-msan-builder', 'msan-builder'])
  ts = datetime.datetime.utcnow().strftime('%Y%m%d%H%M')
  upload_name = 'msan-libs-' + ts + '.zip'

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

  build_body = {
      'steps': steps,
      'timeout': str(6 * 3600) + 's',
      'options': options,
      'images': [
          'gcr.io/oss-fuzz-base/base-msan-builder',
          image,
      ],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(
      projectId='oss-fuzz-base', body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print >> sys.stderr, 'Logs:', build_base_images.get_logs_url(build_id)
  print build_id


if __name__ == '__main__':
  main()
