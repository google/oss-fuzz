#!/usr/bin/python2

"""Starts project build on Google Cloud Builder.

Usage: build.py <project_dir>
"""

import datetime
import os
import pprint
import sys
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build


CONFIGURATIONS = {
  'sanitizer-address' : [ 'SANITIZER=address' ],
  'sanitizer-memory' : [ 'SANITIZER=memory' ],
  'sanitizer-undefined' : [ 'SANITIZER=undefined' ],
  }

DEFAULT_SANITIZERS = ['address', 'undefined']


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)


def load_project_yaml(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  with open(project_yaml_path) as f:
    project_yaml = yaml.safe_load(f)
    project_yaml.setdefault('name', project_name)
    project_yaml.setdefault('image', 
        'gcr.io/clusterfuzz-external/oss-fuzz/' + project_name)
    return project_yaml


def get_build_steps(project_yaml):
  name = project_yaml['name']
  image = project_yaml['image']
  print "Building " + image

  ts = datetime.datetime.now().strftime('%Y%m%d%H%M')

  build_steps = [
          {
              'name': 'gcr.io/cloud-builders/docker',
              'args': [
                  'build',
                  '-t',
                  image,
                  '.',
                  ],
              'dir': 'projects/' + name,
          },
          {
              'name': image,
              'args': [ 'srcmap' ],
              'env': [ 'OSSFUZZ_REVISION=$REVISION_ID' ],
          },
    ]

  sanitizers = project_yaml.get('sanitizers', DEFAULT_SANITIZERS)
  for sanitizer in sanitizers:
    env = CONFIGURATIONS["sanitizer-" + sanitizer]
    out = '/workspace/out/' + sanitizer
    zip_file = name + "-" + sanitizer + "-" + ts + ".zip"

    build_steps.extend([
        {'name': image,
          'env' : env,
          'args': [
            'bash',
            '-c',
            'cd /src/{1} && compile && mkdir -p {0} && cp -Rv /out/* {0}/'.format(out, name),
            ],
          },
        {'name': image,
          'args': [
            'bash',
            '-c',
            'cd {0} && zip -r {1} *'.format(out, zip_file)
          ],
        }])

  return build_steps


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1]
  project_yaml = load_project_yaml(project_dir)

  options = {}
  if "GCB_OPTIONS" in os.environ:
    options = yaml.safe_load(os.environ["GCB_OPTIONS"])
    print "Using options", options


  build_body = {
      'source': {
          'repoSource': {
              'branchName': 'master',
              'projectId': 'clusterfuzz-external',
              'repoName': 'oss-fuzz',
          },
      },
      'steps': get_build_steps(project_yaml),
      'timeout': str(4 * 3600) + 's',
      'options': options,
      'images': [ project_yaml['image'] ],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  pp = pprint.PrettyPrinter(indent=4)
  pp.pprint(build_body)
  pp.pprint(cloudbuild.projects().builds().create(projectId='clusterfuzz-external', body=build_body).execute())


if __name__ == "__main__":
  main()
