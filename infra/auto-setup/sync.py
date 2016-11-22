#!/usr/bin/env python
"""Script to sync CF and Jenkins jobs.""" 

import json
import os
import sys
import urllib2
import xml.etree.ElementTree as ET

import jenkins

BUILD_BUCKET = 'clusterfuzz-builds'
JENKINS_SERVER = ('localhost', 8080)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OSSFUZZ_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def main():
  # Connect to jenkins server.
  jenkins_login = get_jenkins_login()
  server = jenkins.Jenkins('http://%s:%d' % JENKINS_SERVER,
                           username=jenkins_login[0], password=jenkins_login[1])

  for library in get_libraries():
    print 'syncing configs for', library
    try:
      # Create/update jenkins build job.
      sync_jenkins_job(server, library)

    except Exception as e:
      print >>sys.stderr, 'Failed to setup job with exception', e


def get_libraries():
  """Return list of libraries for oss-fuzz."""
  libraries = []
  targets_dir = os.path.join(OSSFUZZ_DIR, 'targets')
  for name in os.listdir(targets_dir):
    if os.path.isdir(os.path.join(targets_dir, name)):
      libraries.append(name)

  if not libraries:
    print >>sys.stderr, 'No libraries found.'

  return libraries


def get_jenkins_login():
  """Returns (username, password) for jenkins."""
  username = os.getenv('JENKINS_USER')
  password = os.getenv('JENKINS_PASS')

  return username, password


def sync_jenkins_job(server, library):
  """Sync the config with jenkins."""
  job_name = 'targets/' + library
  if server.job_exists(job_name):
    # Job already set up.
    # TODO(ochang): Also update jobs if the definition is different.
    return

  job_definition = ET.parse(os.path.join(SCRIPT_DIR, 'jenkins_config',
                                         'base_job.xml'))
  jenkinsfile_location = job_definition.findall('.//definition/scriptPath')[0]
  jenkinsfile_location.text = 'targets/%s/Jenkinsfile' % library

  server.create_job(job_name, ET.tostring(job_definition.getroot()))
  server.build_job(job_name)


if __name__ == '__main__':
  main()
