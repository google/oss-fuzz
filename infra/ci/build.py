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

import enum
import os
import re
import sys
import subprocess
import yaml

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constants

CANARY_PROJECT = 'skcms'

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['afl', 'honggfuzz', 'libfuzzer', 'centipede']
DEFAULT_SANITIZERS = ['address', 'undefined']


def get_changed_files_output():
  """Returns the output of a git command that discovers changed files."""
  branch_commit_hash = subprocess.check_output(
      ['git', 'merge-base', 'HEAD', 'origin/HEAD']).strip().decode()

  return subprocess.check_output(
      ['git', 'diff', '--name-only', branch_commit_hash + '..']).decode()


def get_modified_buildable_projects():
  """Returns a list of all the projects modified in this commit that have a
  build.sh file."""
  git_output = get_changed_files_output()
  projects_regex = '.*projects/(?P<name>.*)/.*\n'
  modified_projects = set(re.findall(projects_regex, git_output))
  projects_dir = os.path.join(get_oss_fuzz_root(), 'projects')
  # Filter out projects without Dockerfile files since new projects and reverted
  # projects frequently don't have them. In these cases we don't want Travis's
  # builds to fail.
  modified_buildable_projects = []
  for project in modified_projects:
    if not os.path.exists(os.path.join(projects_dir, project, 'Dockerfile')):
      print('Project {0} does not have Dockerfile. skipping build.'.format(
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


def should_build_coverage(project_yaml):
  """Returns True if a coverage build should be done based on project.yaml
  contents."""
  # Enable coverage builds on projects that use engines. Those that don't use
  # engines shouldn't get coverage builds.
  engines = project_yaml.get('fuzzing_engines', DEFAULT_ENGINES)
  engineless = 'none' in engines
  if engineless:
    assert_message = ('Forbidden to specify multiple engines for '
                      '"fuzzing_engines" if "none" is specified.')
    assert len(engines) == 1, assert_message
    return False
  if 'wycheproof' in engines:
    return False

  language = project_yaml.get('language')
  if language not in constants.LANGUAGES_WITH_COVERAGE_SUPPORT:
    print(('Project is written in "{language}", '
           'coverage is not supported yet.').format(language=language))
    return False

  return True


def flatten_options(option_list):
  """Generator that flattens |option_list| (a list of sanitizers, architectures
  or fuzzing engines) by returning each element in the list that isn't a
  dictionary. For elements that are dictionaries, the sole key is returned."""
  result = []
  for option in option_list:
    if isinstance(option, dict):
      keys = list(option.keys())
      assert len(keys) == 1
      result.append(keys[0])
      continue
    result.append(option)
  print(result)
  return result


def should_build(project_yaml):
  """Returns True on if the build specified is enabled in the project.yaml."""

  if os.getenv('SANITIZER') == 'coverage':
    # This assumes we only do coverage builds with libFuzzer on x86_64.
    return should_build_coverage(project_yaml)

  def is_enabled(env_var, yaml_name, defaults):
    """Is the value of |env_var| enabled in |project_yaml| (in the |yaml_name|
    section)? Uses |defaults| if |yaml_name| section is unspecified."""
    return os.getenv(env_var) in flatten_options(
        project_yaml.get(yaml_name, defaults))

  return (is_enabled('ENGINE', 'fuzzing_engines', DEFAULT_ENGINES) and
          is_enabled('SANITIZER', 'sanitizers', DEFAULT_SANITIZERS) and
          is_enabled('ARCHITECTURE', 'architectures', DEFAULT_ARCHITECTURES))


def build_project(project):
  """Do the build of |project| that is specified by the environment variables -
  SANITIZER, ENGINE, and ARCHITECTURE."""
  root = get_oss_fuzz_root()
  project_yaml_path = os.path.join(root, 'projects', project, 'project.yaml')
  with open(project_yaml_path) as file_handle:
    project_yaml = yaml.safe_load(file_handle)

  if project_yaml.get('disabled', False):
    print('Project {0} is disabled, skipping build.'.format(project))
    return

  engine = os.getenv('ENGINE')
  sanitizer = os.getenv('SANITIZER')
  architecture = os.getenv('ARCHITECTURE')

  if not should_build(project_yaml):
    print(('Specified build: engine: {0}, sanitizer: {1}, architecture: {2} '
           'not enabled for this project: {3}. Skipping build.').format(
               engine, sanitizer, architecture, project))

    return

  print('Building project', project)
  build_fuzzers(project, engine, sanitizer, architecture)

  run_tests = project_yaml.get('run_tests', True)
  if engine != 'none' and sanitizer != 'coverage' and run_tests:
    check_build(project, engine, sanitizer, architecture)


class BuildModifiedProjectsResult(enum.Enum):
  """Enum containing the return values of build_modified_projects()."""
  NONE_BUILT = 0
  BUILD_SUCCESS = 1
  BUILD_FAIL = 2


def build_modified_projects():
  """Build modified projects. Returns BuildModifiedProjectsResult.NONE_BUILT if
  no builds were attempted. Returns BuildModifiedProjectsResult.BUILD_SUCCESS if
  all attempts succeed, otherwise returns
  BuildModifiedProjectsResult.BUILD_FAIL."""
  projects = get_modified_buildable_projects()
  if not projects:
    return BuildModifiedProjectsResult.NONE_BUILT

  failed_projects = []
  for project in projects:
    try:
      build_project(project)
    except subprocess.CalledProcessError:
      failed_projects.append(project)

  if failed_projects:
    print('Failed projects:', ' '.join(failed_projects))
    return BuildModifiedProjectsResult.BUILD_FAIL

  return BuildModifiedProjectsResult.BUILD_SUCCESS


def is_infra_changed():
  """Returns True if the infra directory was changed."""
  git_output = get_changed_files_output()
  infra_code_regex = '.*infra/.*\n'
  return re.search(infra_code_regex, git_output) is not None


def build_base_images():
  """Builds base images."""
  # TODO(jonathanmetzman): Investigate why caching fails so often and
  # when we improve it, build base-clang as well. Also, move this function
  # to a helper command when we can support base-clang.
  execute_helper_command(['pull_images'])
  images = [
      'base-image',
      'base-builder',
      'base-builder-go',
      'base-builder-javascript',
      'base-builder-jvm',
      'base-builder-python',
      'base-builder-rust',
      'base-builder-swift',
      'base-builder-ruby',
      'base-runner',
  ]
  for image in images:
    try:
      execute_helper_command(['build_image', image, '--no-pull', '--cache'])
    except subprocess.CalledProcessError:
      return 1

  return 0


def build_canary_project():
  """Builds a specific project when infra/ is changed to verify that infra/
  changes don't break things. Returns False if build was attempted but
  failed."""

  try:
    build_project('skcms')
  except subprocess.CalledProcessError:
    return False

  return True


def main():
  """Build modified projects or canary project."""
  os.environ['OSS_FUZZ_CI'] = '1'
  infra_changed = is_infra_changed()
  if infra_changed:
    print('Pulling and building base images first.')
    if build_base_images():
      return 1

  result = build_modified_projects()
  if result == BuildModifiedProjectsResult.BUILD_FAIL:
    return 1

  # It's unnecessary to build the canary if we've built any projects already.
  no_projects_built = result == BuildModifiedProjectsResult.NONE_BUILT
  should_build_canary = no_projects_built and infra_changed
  if should_build_canary and not build_canary_project():
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
