#!/usr/bin/python2
"""Cancels project build on Google Cloud Builder.

Usage: cancel.py <build_id>
"""

import base64
import collections
import datetime
import os
import subprocess
import sys
import time
import urllib
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build


def usage():
  sys.stderr.write('Usage: ' + sys.argv[0] + ' <build_id>\n')
  exit(1)


def main():
  if len(sys.argv) != 2:
    usage()

  build_id = sys.argv[1]

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  print cloudbuild.projects().builds().cancel(projectId='oss-fuzz',
                                              id=build_id,
                                              body={}).execute()


if __name__ == '__main__':
  main()
