import argparse
import collections
import logging
import sys

from googleapiclient.discovery import build as cloud_build
import oauth2client.client
import requests

import build_and_push_test_images
import build_and_run_coverage
import build_project


IMAGE_PROJECT = 'oss-fuzz'
BASE_IMAGES_PROJECT = 'oss-fuzz-base'
TEST_IMAGE_SUFFIX = 'testing'


# class ProjectStatus:
#   def __init__(self, name):
#     self.name = name
#     self.build_id = {'coverage': None, 'fuzzing': None}
#     self.build_id = {'coverage': None, 'fuzzing': None}
#     self.fuzzing_build_status = None
#     self.fuzzing_build_id = None
#     self.fuzzing_build_status = None
#     self.prev_fuzzing_build_status = None
#     self.prev_coverage_build_status = None


def _get_production_build_statuses(build_type, statuses=None):
  if statuses is None:
    statuses = collections.defaultdict(lambda: {'coverage': False,
                                                'fuzzing': False})
  if build_type == 'fuzzing':
    filename = 'status.json'
  elif build_type == 'coverage':
    filename = 'status-coverage.json'
  else:
    assert None

  request = requests.get(
      f'https://oss-fuzz-build-logs.storage.googleapis.com/{filename}')
  project_statuses = request.json()['projects']
  for project in project_statuses:
    name = project['name']
    # !!! 0 len?
    success = project['history'][0]['success']
    statuses[name][build_type] = success
  return statuses


def get_args():
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(sys.argv[0], description='Test projects')
  parser.add_argument('projects', help='Projects.', nargs='*')
  parser.add_argument('--testing',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Upload to testing buckets.')
  parser.add_argument('--sanitizers',
                      required=True,
                      nargs='+',
                      help='Sanitizers.')
  parser.add_argument('--fuzzing-engines',
                      required=True,
                      nargs='+',
                      help='Fuzzing engines.')
  parser.add_argument('--branch',
                      required=False,
                      default=None,
                      help='Use specified OSS-Fuzz branch.')
  return parser.parse_args()


def get_production_build_statuses():
  statuses = _get_production_build_statuses('fuzzing')
  statuses = _get_production_build_statuses('coverage', statuses)
  return statuses


def build_types_requested(specified_sanitizers):
  coverage_requested = 'coverage' in specified_sanitizers
  fuzzing_requested = False
  if len(specified_sanitizers) != 1:
    fuzzing_requested = True
  elif specified_sanitizers[0] != 'coverage':
    fuzzing_requested = True
  return fuzzing_requested, coverage_requested

def get_projects(specified_projects, statuses, build_type):
  statuses = get_production_build_statuses()
  buildable_projects = []

  for project in specified_projects:
    if project not in statuses:
      buildable_projects.append(project)
      continue
    if statuses[project][build_type]:
      buildable_projects.append(project)
      continue

    logging.info('Skipping %s, last build failed.', project)

  return buildable_projects

def _do_test_builds(args, config, credentials, build_type, builds=None):
  if builds is None:
    builds = collections.defaultdict(lambda: {'coverage': None,
                                              'fuzzing': None})
  if build_type == 'fuzzing':
    get_build_steps_func = build_project.get_build_steps
    sanitizers = args.sanitizers
  else:
    get_build_steps_func = build_and_run_coverage.get_build_steps
    sanitizers = ['coverage']

  statuses = get_production_build_statuses()
  projects = get_projects(args.projects, statuses, build_type)
  for project_name in projects:
    logging.info('Getting steps for: "%s".', project_name)
    try:
      project_yaml, dockerfile_contents = (
          build_project.get_project_data(project_name))
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      continue


    project_yaml['sanitizers'] = list(
        set(project_yaml['sanitizers']).intersection(set(sanitizers)))

    project_yaml['fuzzing_engines'] = list(set(
        project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      logging.info('Nothing to build for this project: %s.', project_name)
      continue

    steps = get_build_steps_func(
        project_name, project_yaml,
        dockerfile_contents, IMAGE_PROJECT,
        BASE_IMAGES_PROJECT, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      continue

    builds[project_name][build_type] = (
        build_project.run_build(project_name, steps, credentials, build_type))

  return builds


def get_build_status_from_gcb(cloudbuild_api, build_id):
  build_result = cloudbuild_api.get(
      projectId=IMAGE_PROJECT, id=build_id).execute()
  return build_result['status']

def wait_on_builds(builds, credentials):
  results = collections.defaultdict(
      lambda: {'coverage': False, 'fuzzing': False})

  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False)
  cloudbuild_api = cloudbuild.projects().builds()

  wait_more = True

  while builds:
    for project, build_ids in list(builds.items()):
      fuzzing_build_id = build_ids['fuzzing']
      if fuzzing_build_id:
        status = get_build_status_from_gcb(cloudbuild_api, fuzzing_build_id)
        if status not in ('SUCCESS', 'FAILURE', 'TIMEOUT'):
          continue
        results[project]['fuzzing'] = status == 'SUCCESS'
      elif 'fuzzing' in results[project]:
        del results[project]['fuzzing']

      fuzzing_build_id = build_ids['coverage']
      if coverage_build_id:
        status = get_build_status_from_gcb(cloudbuild_api, fuzzing_build_id)
        if status not in ('SUCCESS', 'FAILURE', 'TIMEOUT'):
          continue
        results[project]['coverage'] = status == 'SUCCESS'
      elif 'coverage' in results[project]:
        del results[project]['coverage']

      if all(results[project]):
        del builds[project]
      print('waiting', builds)


def do_test_builds(args):
  config = build_project.Config(True, TEST_IMAGE_SUFFIX, args.branch, False)
  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  builds = _do_test_builds(args, config, credentials, 'fuzzing')
  _do_test_builds(args, config, credentials, 'coverage', builds)
  wait_on_builds(builds, credentials)


def main():
  logging.basicConfig(level=logging.INFO)
  args = get_args()
  build_and_push_test_images.build_and_push_images(TEST_IMAGE_SUFFIX)
  return do_test_builds(args)

if __name__ == '__main__':
  main()
