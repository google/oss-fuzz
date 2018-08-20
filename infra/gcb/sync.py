#!/usr/bin/env python
"""Script to sync CF and Jenkins jobs."""

import json
import os
import re
import sys
import yaml

import jenkins

JENKINS_SERVER = ('localhost', 8080)

JOB_TEMPLATES = [
    {'prefix': 'projects/', 'config': 'base_job.xml'},
    {'prefix': 'coverage/', 'config': 'coverage_job.xml'},
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OSSFUZZ_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

VALID_PROJECT_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


def main():
  # Connect to jenkins server.
  jenkins_login = get_jenkins_login()
  server = jenkins.Jenkins(
      'http://%s:%d' % JENKINS_SERVER,
      username=jenkins_login[0],
      password=jenkins_login[1])

  for project in get_projects():
    print 'syncing configs for', project
    try:
      # Create/update jenkins build job.
      sync_jenkins_job(server, project)

    except Exception as e:
      print >> sys.stderr, 'Failed to setup job with exception', e


def _has_dockerfile(project_dir):
  """Whether or not the project has a Dockerfile."""
  if os.path.exists(os.path.join(project_dir, 'Dockerfile')):
    return True

  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  if not os.path.exists(project_yaml_path):
    return False

  with open(project_yaml_path) as f:
    project_info = yaml.safe_load(f)

  return 'dockerfile' in project_info


def get_projects():
  """Return list of projects for oss-fuzz."""
  projects = []
  projects_dir = os.path.join(OSSFUZZ_DIR, 'projects')
  for name in os.listdir(projects_dir):
    full_path = os.path.join(projects_dir, name)
    if not os.path.isdir(full_path) or not _has_dockerfile(full_path):
      continue

    if not VALID_PROJECT_NAME.match(name):
      print >> sys.stderr, 'Invalid project name:', name
      continue

    projects.append(name)

  if not projects:
    print >> sys.stderr, 'No projects found.'

  return projects


def get_jenkins_login():
  """Returns (username, password) for jenkins."""
  username = os.getenv('JENKINS_USER')
  password = os.getenv('JENKINS_PASS')

  return username, password


def sync_jenkins_job(server, project):
  """Sync the config with jenkins."""
  project_yaml = os.path.join(OSSFUZZ_DIR, 'projects', project, 'project.yaml')
  with open(project_yaml, 'r') as f:
    project_json_string = json.dumps(json.dumps(yaml.safe_load(f)))

  for job in JOB_TEMPLATES:
    job_name = job['prefix'] + project
    with open(os.path.join(SCRIPT_DIR, 'jenkins_config', job['config'])) as f:
      job_config_xml = f.read()

    if server.job_exists(job_name):
      server.reconfig_job(job_name, job_config_xml)
    else:
      server.create_job(job_name, job_config_xml)
      server.build_job(job_name)


if __name__ == '__main__':
  main()
