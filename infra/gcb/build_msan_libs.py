#!/usr/bin/python2

"""Build base images on Google Cloud Builder.

Usage: build_base_images.py
"""

import os
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

import build_base_images


def main():
  options = {}
  if "GCB_OPTIONS" in os.environ:
    options = yaml.safe_load(os.environ["GCB_OPTIONS"])

  build_body = {
      'steps': build_base_images.get_steps(['msan-builder']),
      'timeout': str(6 * 3600) + 's',
      'options': options,
      'images': [
          'gcr.io/oss-fuzz-base/msan-builder',
       ],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(projectId='oss-fuzz-base', body=build_body).execute()
  build_id =  build_info['metadata']['build']['id']

  print build_id


if __name__ == "__main__":
  main()
