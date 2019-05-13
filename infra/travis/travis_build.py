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

DEFAULT_FUZZING_ENGINES = ['afl', 'libfuzzer']
DEFAULT_SANITIZERS = ['address', 'undefined']


def get_modified_projects():
  """Get a list of all the projects modified in this commit."""
  master_head_sha = subprocess.check_output(
      ['git', 'merge-base', 'HEAD', 'FETCH_HEAD']).decode().strip()
  output = subprocess.check_output(
      ['git', 'diff', '--name-only', 'HEAD', master_head_sha]).decode()
  projects_regex = '.*projects/(?P<name>.*)/.*\n'
  return set(re.findall(projects_regex, output))


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


def build_fuzzers(project, sanitizer, engine, architecture='x86_64'):
  """Execute helper.py's build_fuzzers command on |project|. Build the fuzzers
  with |sanitizer| and |engine|."""
  execute_helper_command([
      'build_fuzzers', project, '--engine', engine, '--sanitizer', sanitizer,
      '--architecture', architecture
  ])


def check_build(project, sanitizer, engine):
  """Execute helper.py's check_build command on |project|, assuming it was most
  recently built with |sanitizer| and |engine|."""
  execute_helper_command(
      ['check_build', project, '--engine', engine, '--sanitizer', sanitizer])


def build_project(project):
  """Do all build of |project|."""
  print('Building project', project)
  root = get_oss_fuzz_root()
  project_yaml_path = os.path.join(root, 'projects', project, 'project.yaml')
  with open(project_yaml_path) as fp:
    project_yaml = yaml.safe_load(fp)

  if project_yaml.get('disabled', False):
    return

  fuzzing_engines = project_yaml.get('fuzzing_engines', DEFAULT_FUZZING_ENGINES)
  if 'none' in fuzzing_engines:
    # no engine builds always use ASAN.
    build_fuzzers(project, 'address', 'none')
    return

  if 'afl' in fuzzing_engines:
    # AFL builds always use ASAN.
    build_fuzzers(project, 'address', 'afl')
    check_build(project, 'address', 'afl')

  if 'libfuzzer' not in fuzzing_engines:
    return

  for sanitizer in project_yaml.get('sanitizers', DEFAULT_SANITIZERS):
    build_fuzzers(project, sanitizer, 'libfuzzer')
    check_build(project, sanitizer, 'libfuzzer')

  if 'i386' in project_yaml.get('architectures', []):
    # i386 builds always use libFuzzer and ASAN.
    build_fuzzers(project, 'address', 'libfuzzer', 'i386')
    check_build(project, 'address', 'libfuzzer')


def main():
  projects = get_modified_projects()
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
