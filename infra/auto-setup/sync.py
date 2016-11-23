#!/usr/bin/env python
"""Script to sync CF and Jenkins jobs.""" 

import json
import os
import sys
import urllib2
import yaml
import xml.etree.ElementTree as ET

import jenkins

BUILD_BUCKET = 'clusterfuzz-builds'
JENKINS_SERVER = ('localhost', 8080)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OSSFUZZ_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

SCRIPT_TEMPLATE = """
def libfuzzerBuild = fileLoader.fromGit('infra/libfuzzer-pipeline.groovy', 'https://github.com/google/oss-fuzz.git')
libfuzzerBuild { target_json = %(target_json)s }
"""

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
  target_yaml = os.path.join(OSSFUZZ_DIR, 'targets', library, 'target.yaml')
  with open(target_yaml, 'r') as f:
    target_json_string = json.dumps(json.dumps(yaml.load(f)))
                             
  job_name = 'targets/' + library
  job_definition = ET.parse(os.path.join(SCRIPT_DIR, 'jenkins_config',
                                         'base_job.xml'))
  script = job_definition.findall('.//definition/script')[0]
  script.text = SCRIPT_TEMPLATE % { "target_json": target_json_string} 
  job_config_xml = ET.tostring(job_definition.getroot())

  if server.job_exists(job_name):
    server.reconfig_job(job_name, job_config_xml)
  else:
    server.create_job(job_name, job_config_xml)
    server.build_job(job_name)


if __name__ == '__main__':
  main()
