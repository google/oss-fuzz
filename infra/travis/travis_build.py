#!/usr/bin/env python
# Copyright 2019 Google Inc.
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
"""Build modified projects."""

from __future__ import print_function

import os
import re
import subprocess
import yaml

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['afl', 'libfuzzer']
DEFAULT_SANITIZERS = ['address', 'undefined']


def get_modified_buildable_projects():
  """Returns a list of all the projects modified in this commit that have a
  build.sh file."""
  master_head_sha = subprocess.check_output(
      ['git', 'merge-base', 'HEAD', 'FETCH_HEAD']).decode().strip()
  output = subprocess.check_output(
      ['git', 'diff', '--name-only', 'HEAD', master_head_sha]).decode()
  projects_regex = '.*projects/(?P<name>.*)/.*\n'
  modified_projects = set(re.findall(projects_regex, output))
  projects_dir = os.path.join(get_oss_fuzz_root(), 'projects')
  # Filter out projects without build.sh files since new projects and reverted
  # projects frequently don't have them. In these cases we don't want Travis's
  # builds to fail.
  modified_buildable_projects = []
  for project in modified_projects:
    if not os.path.exists(os.path.join(projects_dir, project, 'build.sh')):
      print('Project {0} does not have a build.sh. skipping build.'.format(
          project))
      continue
    modified_buildable_projects.append(project)
  return modified_buildable_projects


def get_oss_fuzz_root():
  """Get the absolute path of the root of the oss-fuzz checkout."""
  script_path = os.path.realpath(__file__)
  return os.path.abspath(
      os.path.dirname(os.path.dirname(os.path.dirname(script_path))))


def execute_helper_command(helper_command):
  """Execute |helper_command| using helper.py."""
  root = get_oss_fuzz_root()
  script_path = os.path.join(root, 'infra', 'helper.py')
  command = ['python', script_path] + helper_command
  print('Running command: %s' % ' '.join(command))
  subprocess.check_call(command)


def build_fuzzers(project, engine, sanitizer, architecture):
  """Execute helper.py's build_fuzzers command on |project|. Build the fuzzers
  with |engine| and |sanitizer| for |architecture|."""
  execute_helper_command([
      'build_fuzzers', project, '--engine', engine, '--sanitizer', sanitizer,
      '--architecture', architecture
  ])


def check_build(project, engine, sanitizer, architecture):
  """Execute helper.py's check_build command on |project|, assuming it was most
  recently built with |engine| and |sanitizer| for |architecture|."""
  execute_helper_command([
      'check_build', project, '--engine', engine, '--sanitizer', sanitizer,
      '--architecture', architecture
  ])


def should_build(project_yaml):
  """Is the build specified by travis enabled in the |project_yaml|?"""

  def is_enabled(env_var, yaml_name, defaults):
    """Is the value of |env_var| enabled in |project_yaml| (in the |yaml_name|
    section)? Uses |defaults| if |yaml_name| section is unspecified."""
    return os.getenv(env_var) in project_yaml.get(yaml_name, defaults)

  return (is_enabled('TRAVIS_ENGINE', 'fuzzing_engines', DEFAULT_ENGINES) and
          is_enabled('TRAVIS_SANITIZER', 'sanitizers', DEFAULT_SANITIZERS) and
          is_enabled('TRAVIS_ARCHITECTURE', 'architectures',
                     DEFAULT_ARCHITECTURES))


def build_project(project):
  """Do the build of |project| that is specified by the TRAVIS_* environment
  variables (TRAVIS_SANITIZER, TRAVIS_ENGINE, and TRAVIS_ARCHITECTURE)."""
  root = get_oss_fuzz_root()
  project_yaml_path = os.path.join(root, 'projects', project, 'project.yaml')
  with open(project_yaml_path) as fp:
    project_yaml = yaml.safe_load(fp)

  if project_yaml.get('disabled', False):
    print('Project {0} is disabled, skipping build.'.format(project))
    return

  engine = os.getenv('TRAVIS_ENGINE')
  sanitizer = os.getenv('TRAVIS_SANITIZER')
  architecture = os.getenv('TRAVIS_ARCHITECTURE')

  if not should_build(project_yaml):
    print(('Specified build: engine: {0}, sanitizer: {1}, architecture: {2} '
           'not enabled for this project: {3}. skipping build.').format(
               engine, sanitizer, architecture, project))

    return

  print('Building project', project)
  build_fuzzers(project, engine, sanitizer, architecture)
  if engine != 'none':
    check_build(project, engine, sanitizer, architecture)


def main():
  projects = get_modified_buildable_projects()
  failed_projects = []
  for project in projects:
    try:
      build_project(project)
    except subprocess.CalledProcessError:
      failed_projects.append(project)

  if failed_projects:
    print('Failed projects:', ' '.join(failed_projects))
    exit(1)


if __name__ == '__main__':
  main()
