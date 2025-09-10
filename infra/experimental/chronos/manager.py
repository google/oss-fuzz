# Copyright 2025 Google LLC
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
"""Module for managing Chronos cached builds."""

import os
import sys
import logging
import argparse
import time
import json
import requests
import subprocess
from enum import Enum

import bad_patch

logger = logging.getLogger(__name__)

OSS_FUZZ_BUILD_HISTORY_URL = 'https://oss-fuzz-build-logs.storage.googleapis.com/status.json'
OSS_FUZZ_BUILD_HISTORY = None

RUN_TEST_HEURISTIC_0 = 'make test'
RUN_TEST_HEURISTIC_1 = 'make tests'
RUN_TEST_HEURISTIC_2 = 'make check'

RUN_TESTS_TO_TRY = [
    RUN_TEST_HEURISTIC_0, RUN_TEST_HEURISTIC_1, RUN_TEST_HEURISTIC_2
]


class ContainerRedirection(Enum):
  """Enum for output redirection."""
  NONE = 1
  FILE = 2
  SILENT = 3


def _get_oss_fuzz_build_status(project):
  """Returns the build status of a project in OSS-Fuzz."""
  global OSS_FUZZ_BUILD_HISTORY
  if OSS_FUZZ_BUILD_HISTORY is None:
    # Load the build history from a file or other source.
    # This is a placeholder for actual implementation.
    build_status = requests.get(OSS_FUZZ_BUILD_HISTORY_URL)
    OSS_FUZZ_BUILD_HISTORY = json.loads(build_status.text)

  for project_data in OSS_FUZZ_BUILD_HISTORY.get('projects', []):
    if project_data['name'] == project:
      logger.info('Found project %s in OSS-Fuzz build history.', project)
      return project_data.get('history', [{
          'success': False
      }])[0].get('success', False)

  logger.info('Project %s not found in OSS-Fuzz build history.', project)
  return False


def _get_project_cached_named(project, sanitizer='address'):
  """Gets the name of the cached project image."""
  return f'us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/{project}-ofg-cached-{sanitizer}'


def _get_project_cached_named_local(project, sanitizer='address'):
  return f'{project}-origin-{sanitizer}'


def build_project_image(project, container_output='stdout'):
  """Build OSS-Fuzz base image for a project."""

  if container_output == 'file':
    out_idx = 0
    stdout_file = os.path.join('projects', project,
                               'build_image_stdout.%d.out' % (out_idx))
    while os.path.isfile(stdout_file):
      out_idx += 1
      stdout_file = os.path.join('projects', project,
                                 'build_image_stdout.%d.out' % (out_idx))
    stderr_file = os.path.join('projects', project,
                               'build_image_stderr.%d.err' % (out_idx))
    stdout_fp = open(stdout_file, 'w')
    stderr_fp = open(stderr_file, 'w')
  elif container_output == 'silent':
    stdout_fp = subprocess.DEVNULL
    stderr_fp = subprocess.DEVNULL
  else:
    stdout_fp = None
    stderr_fp = None

  cmd = ['docker', 'build', '-t', 'gcr.io/oss-fuzz/' + project, '.']
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          cwd=os.path.join('projects', project),
                          stdout=stdout_fp,
                          stderr=stderr_fp)
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()
  except subprocess.CalledProcessError as e:
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()


def build_cached_project(project,
                         cleanup=True,
                         sanitizer='address',
                         container_output='stdout'):
  """Build cached image for a project."""
  container_name = _get_project_cached_named_local(project, sanitizer)

  # Clean up the container if it exists.
  if cleanup:
    try:
      subprocess.check_call(['docker', 'container', 'rm', '-f', container_name],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      pass

  if container_output == 'file':
    out_idx = 0
    stdout_file = os.path.join('projects', project,
                               'build_cache_stdout.%d.out' % (out_idx))
    while os.path.isfile(stdout_file):
      out_idx += 1
      stdout_file = os.path.join('projects', project,
                                 'build_cache_stdout.%d.out' % (out_idx))
    stderr_file = os.path.join('projects', project,
                               'build_cache_stderr.%d.err' % (out_idx))
    stdout_fp = open(stdout_file, 'w')
    stderr_fp = open(stderr_file, 'w')
  elif container_output == 'silent':
    stdout_fp = subprocess.DEVNULL
    stderr_fp = subprocess.DEVNULL
  else:
    stdout_fp = None
    stderr_fp = None

  project_language = 'c++'
  cwd = os.getcwd()
  # Build the cached image.
  cmd = [
      'docker', 'run', '--env=SANITIZER=' + sanitizer,
      '--env=CCACHE_DIR=/workspace/ccache',
      f'--env=FUZZING_LANGUAGE={project_language}',
      '--env=CAPTURE_REPLAY_SCRIPT=1', f'--name={container_name}',
      f'-v={cwd}/ccaches/{project}/ccache:/workspace/ccache',
      f'-v={cwd}/build/out/{project}/:/out/', f'gcr.io/oss-fuzz/{project}',
      'bash', '-c',
      '"export PATH=/ccache/bin:\$PATH && compile && cp -n /usr/local/bin/replay_build.sh \$SRC/"'
  ]

  start = time.time()
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=stdout_fp,
                          stderr=stderr_fp)
    end = time.time()
    logger.info('%s vanilla build Succeeded: Duration: %.2f seconds', project,
                end - start)
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()
  except subprocess.CalledProcessError as e:
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()
    end = time.time()
    logger.info('%s vanilla build Failed: Duration: %.2f seconds', project,
                end - start)
    return False

  # Copy the coverage script into the container.
  # Ensure we're are the right cwd.
  coverage_host_script = os.path.join('infra', 'experimental', 'chronos',
                                      'coverage_test_collection.py')
  if not os.path.exists(coverage_host_script):
    logger.info('Coverage script does not exist at %s', coverage_host_script)
  else:
    # Copy the coverage script into the container.
    logger.info('Copying coverage script to container: %s', container_name)
    cmd = [
        'docker', 'container', 'cp', coverage_host_script,
        f'{container_name}:/usr/local/bin/coverage_test_collection.py'
    ]
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

  # Save the container.
  cmd = [
      'docker', 'container', 'commit', '-c', '"ENV REPLAY_ENABLED=1"', '-c',
      '"ENV CAPTURE_REPLAY_SCRIPT=1"', container_name,
      _get_project_cached_named(project, sanitizer)
  ]
  logger.info('Saving image: [%s]', ' '.join(cmd))
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

  except subprocess.CalledProcessError as e:
    logger.error('Failed to save cached image: %s', e)

    return False
  return True


def check_cached_replay(project,
                        sanitizer='address',
                        container_output='stdout',
                        silent_replays=False,
                        integrity_test=False):
  """Checks if a cache build succeeds and times is."""
  build_project_image(project, container_output=container_output)
  build_cached_project(project,
                       sanitizer=sanitizer,
                       container_output=container_output)

  start = time.time()
  failed = []
  base_cmd = 'export PATH=/ccache/bin:$PATH && rm -rf /out/* && compile'
  cmd = [
      'docker',
      'run',
      '--rm',
      '--env=SANITIZER=' + sanitizer,
      '--env=FUZZING_LANGUAGE=c++',
      '-v=' + os.path.join(os.getcwd(), 'build', 'out', project) + ':/out',
      '-v=' + os.path.join(os.getcwd(), 'infra', 'experimental', 'chronos') +
      ':/chronos',
      '--name=' + project + '-origin-' + sanitizer + '-replay-recached',
      _get_project_cached_named(project, sanitizer),
      '/bin/bash',
      '-c',
  ]

  # Configure output
  if silent_replays:
    stdout_fp = subprocess.DEVNULL
    stderr_fp = subprocess.DEVNULL
  else:
    stdout_fp = None
    stderr_fp = None

  if integrity_test:
    # Use different bad patches to test the cached replay build
    failed = []
    for bad_patch_name, bad_patch_map in bad_patch.BAD_PATCH_GENERATOR.items():
      # Generate bad patch command using different approaches
      expected_rc = bad_patch_map['rc']
      bad_patch_command = f'python3 -m pip install -r /chronos/requirements.txt && python3 /chronos/bad_patch.py {bad_patch_name}'
      cmd_to_run = cmd[:]
      cmd_to_run.append(
          f'"set -euo pipefail && {bad_patch_command} && {base_cmd}"')
      print(' '.join(cmd_to_run))
      # Run the cached replay script with bad patches
      result = subprocess.run(' '.join(cmd_to_run),
                              shell=True,
                              stdout=stdout_fp,
                              stderr=stderr_fp)

      if result.returncode not in expected_rc:
        failed.append(bad_patch_name)
        logger.info(('%s check cached replay failed on bad patches %s. '
                     'Return code: %d. Expected return code: %s'), project,
                    bad_patch_name, result.returncode, str(expected_rc))

      if failed:
        logger.info(
            '%s check cached replay failed to detect these bad patches: %s',
            project, ' '.join(failed))
      else:
        logger.info('%s check cached replay success to detect all bad patches.',
                    project)
  else:
    # Normal run with no integrity check
    cmd.append(f'"{base_cmd}"')
    subprocess.run(' '.join(cmd),
                   shell=True,
                   stdout=stdout_fp,
                   stderr=stderr_fp)

  end = time.time()
  logger.info('%s check cached replay completion time: %.2f seconds', project,
              (end - start))


def check_test(project,
               sanitizer='address',
               container_output='stdout',
               run_full_cache_replay=False):
  """Run the `run_tests.sh` script for a specific project. Will
    build a cached container first."""

  script_path = os.path.join('projects', project, 'run_tests.sh')

  if not os.path.exists(script_path):
    logger.info('Error: The script for project "%s" does not exist at %s',
                project, script_path)
    sys.exit(1)

  # Build an OSS-Fuzz image of the project
  if run_full_cache_replay:
    check_cached_replay(
        project,
        sanitizer,
        container_output,
        silent_replays=(True if container_output == 'silent' else False))
  else:
    build_project_image(project, container_output)
    # build a cached version of the project
    if not build_cached_project(
        project, sanitizer=sanitizer, container_output=container_output):
      return False

  # Run the test script
  cmd = [
      'docker', 'run', '--rm', '--network', 'none', '-ti',
      _get_project_cached_named(project, sanitizer), '/bin/bash', '-c',
      '"chmod +x /src/run_tests.sh && /src/run_tests.sh"'
  ]

  if container_output == 'file':
    out_idx = 0
    stdout_file = os.path.join('projects', project, 'stdout.%d.out' % (out_idx))
    while os.path.isfile(stdout_file):
      out_idx += 1
      stdout_file = os.path.join('projects', project,
                                 'stdout.%d.out' % (out_idx))
    stderr_file = os.path.join('projects', project, 'stderr.%d.err' % (out_idx))
    stdout_fp = open(stdout_file, 'w')
    stderr_fp = open(stderr_file, 'w')
  elif container_output == 'silent':
    stdout_fp = subprocess.DEVNULL
    stderr_fp = subprocess.DEVNULL
  else:
    stdout_fp = None
    stderr_fp = None

  start = time.time()
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=stdout_fp,
                          stderr=stderr_fp)
    succeeded = True
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()
  except subprocess.CalledProcessError as e:
    succeeded = False
    if container_output == 'file':
      stdout_fp.close()
      stderr_fp.close()
  end = time.time()

  logger.info('%s test completion %s: Duration of run_tests.sh: %.2f seconds',
              project, 'failed' if not succeeded else 'succeeded',
              (end - start))
  return succeeded


def _get_project_language(project):
  """Returns the language of the project."""
  project_path = os.path.join('projects', project)
  if not os.path.isdir(project_path):
    return ''

  # Check for a .lang file or similar to determine the language
  project_yaml = os.path.join(project_path, 'project.yaml')
  if os.path.exists(project_yaml):
    with open(project_yaml, 'r') as f:
      for line in f:
        if 'language' in line:
          return line.split(':')[1].strip()

  # Default to C++ if no specific language file is found
  return ''


def _autogenerate_run_tests_script(project, container_output):
  """Autogenerate `run_tests.sh` for a project."""
  project_path = os.path.join('projects', project)
  run_tests_script = os.path.join(project_path, 'run_tests.sh')

  for run_test_script in RUN_TESTS_TO_TRY:
    with open(run_tests_script, 'w') as f:
      f.write('#!/bin/bash\n')
      f.write('set -eux\n')
      f.write(run_test_script + '\n')
      f.write('echo "Running tests for project: {}"\n'.format(project))
      # Add more commands as needed to run tests
    os.chmod(run_tests_script, 0o755)
    logger.info('Created run_tests.sh for %s', project)

    # Adjust the Dockerfile to copy it in
    dockerfile_path = os.path.join(project_path, 'Dockerfile')

    add_run_tests = False
    with open(dockerfile_path, 'r') as f:
      if 'COPY run_tests.sh' not in f.read():
        add_run_tests = True
    if add_run_tests:
      with open(dockerfile_path, 'a') as f:
        f.write('\n# Copy the autogenerated run_tests.sh script\n')
        f.write('COPY run_tests.sh $SRC/run_tests.sh\n')
        f.write('RUN chmod +x $SRC/run_tests.sh\n')

    succeeded = check_test(project, container_output=container_output)

    # If it succeeded initially, then make sure that it actually succeeds
    # to generate a coverage report. if it does not, then it means the
    # generation actually failed.
    coverage_success = extract_test_coverage(project)
    if not coverage_success:
      logger.error('Coverage generation failed for %s', project)
      succeeded = False

    success_file = os.path.join(project_path, 'run_tests.succeeded')
    with open(success_file, 'a') as f:
      f.write('Auto-generation succeeded: {}\n'.format(succeeded))
    if succeeded:
      logger.info('Autogenerated run_tests.sh for %s successfully.', project)
      break


def autogen_projects(apply_filtering=False,
                     max_projects_to_try=1,
                     container_output='stdout',
                     projects_to_target=[]):
  """Autogenerate `run_tests.sh` for all projects."""
  if projects_to_target:
    projects = projects_to_target
  else:
    projects = os.listdir('projects')
  projects_tries = 0
  for project in projects:
    if projects_tries >= max_projects_to_try:
      logger.info('Reached maximum number of projects to try: %d',
                  max_projects_to_try)
      break

    project_path = os.path.join('projects', project)
    if not os.path.isdir(project_path):
      continue

    # Ensure the project language is C or C++
    if not _get_project_language(project).lower() in ['c', 'c++']:
      continue

    run_tests_script = os.path.join(project_path, 'run_tests.sh')
    if os.path.exists(run_tests_script):
      logger.info('Skipping %s, run_tests.sh already exists.', project)
      continue

    if apply_filtering:
      # Apply filtering logic to increase performance
      build_script = os.path.join(project_path, 'build.sh')
      if not os.path.exists(build_script):
        logger.warning('Skipping %s, build.sh does not exist.', project)
        continue
      with open(build_script, 'r') as f:
        lines = f.readlines()
      # Filter out lines that are not relevant for the test script
      filtered_lines = [line for line in lines if 'make' in line]
      if not filtered_lines:
        logger.warning('Skipping %s, no relevant lines found in build.sh.',
                       project)
        continue

    # It only makes sense to autogenerate if the project actually builds, so
    # query OSS-Fuzz to make sure the most recent build was successful.

    if not _get_oss_fuzz_build_status(project):
      logger.warning('Skipping %s, most recent build was not successful.',
                     project)
      continue

    projects_tries += 1
    logger.info('Autogenerating run_tests.sh for %s', project)
    _autogenerate_run_tests_script(project, container_output)


def extract_test_coverage(project):
  build_project_image(project, container_output='')
  build_cached_project(project, sanitizer='coverage', container_output='stdout')

  os.makedirs(os.path.join('build', 'out', project), exist_ok=True)

  cmd = [
      'docker', 'run', '--rm', '--network', 'none', '-v',
      '%s:/out' % (os.path.join(os.getcwd(), 'build', 'out', project)), '-ti',
      _get_project_cached_named(project, 'coverage'), '/bin/bash', '-c',
      ('"chmod +x /src/run_tests.sh && '
       'find /src/ -name "*.profraw" -exec rm -f {} \\; && '
       '/src/run_tests.sh && '
       'python3 /usr/local/bin/coverage_test_collection.py && '
       'chmod -R 755 /out/test-html-generation/"')
  ]
  try:
    subprocess.check_call(' '.join(cmd), shell=True)
  except subprocess.CalledProcessError as e:
    logger.error('Error occurred while running coverage collection: %s', e)
    return False

  # If the summary file is created, dump the total lines covered.
  if os.path.isfile(
      os.path.join('build', 'out', project, 'test-html-generation',
                   'summary.json')):
    with open(
        os.path.join('build', 'out', project, 'test-html-generation',
                     'summary.json'), 'r') as f:
      summary = json.load(f)
      total_lines_covered = summary['data'][0]['totals']['lines']
      logger.info('Total lines covered for %s: %s', project,
                  json.dumps(total_lines_covered))
  return True


def parse_args():
  """Parses command line arguments for the manager script."""
  parser = argparse.ArgumentParser(
      'manager.py',
      description='Chronos Manager: a tool for managing cached OSS-Fuzz builds.'
  )
  subparsers = parser.add_subparsers(dest='command')

  check_test_parser = subparsers.add_parser(
      'check-test', help='Checks run_test.sh for specific project.')
  check_test_parser.add_argument(
      '--projects',
      nargs='+',
      required=True,
      type=str,
      help='The name of the projects to check (e.g., "libpng").',
  )
  check_test_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use (default: address).')
  check_test_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')
  check_test_parser.add_argument(
      '--run-full-cache-replay',
      action='store_true',
      help=
      'If set, will run the full cache replay instead of just checking the script.'
  )

  check_replay_script_parser = subparsers.add_parser(
      'check-replay-script',
      help='Checks if the replay script works for a specific project.')

  check_replay_script_parser.add_argument(
      'project', help='The name of the project to check.')
  check_replay_script_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')

  check_replay_script_integrity_parser = subparsers.add_parser(
      'check-replay-script-integrity',
      help=
      ('Checks if the replay script works for a specific project. '
       'Integrity of the replay script is also tested with different bad patches.'
      ))

  check_replay_script_integrity_parser.add_argument(
      'project', help='The name of the project to check.')
  check_replay_script_integrity_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')

  build_cached_image_parser = subparsers.add_parser(
      'build-cached-image',
      help='Builds a cached image for a specific project.')
  build_cached_image_parser.add_argument(
      'project', help='The name of the project to build.')
  build_cached_image_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')
  build_cached_image_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')

  autogen_tests_parser = subparsers.add_parser(
      'autogen-tests',
      help='Tries to autogenerate `run_tests.sh` for projects.')
  autogen_tests_parser.add_argument(
      '--apply-filtering',
      action='store_true',
      help=
      'If set, applies filtering to increase performance but test on fewer projects that are more likely to succeed.'
  )
  autogen_tests_parser.add_argument(
      '--max-projects-to-try',
      type=int,
      default=1,
      help='Maximum number of projects to try (default: 1).')
  autogen_tests_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')
  autogen_tests_parser.add_argument(
      '--projects',
      default='',
      nargs='+',
      help=
      'The name of the projects to autogenerate tests for. If not specified, all projects will be considered.'
  )

  build_many_caches = subparsers.add_parser(
      'build-many-caches',
      help='Builds cached images for multiple projects in parallel.')
  build_many_caches.add_argument(
      '--projects',
      nargs='+',
      required=True,
      help='List of projects to build cached images for.')
  build_many_caches.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')
  build_many_caches.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')
  build_many_caches.add_argument('--silent-replays', action='store_true')

  extract_coverage_parser = subparsers.add_parser(
      'extract-test-coverage',
      help='Extract code coverage reports from run_tests.sh script')
  extract_coverage_parser.add_argument(
      'project', help='The name of the project to extract coverage for.')

  return parser.parse_args()


def main():
  """Main"""
  logging.basicConfig(level=logging.INFO)

  args = parse_args()

  if args.command == 'check-test':
    if len(args.projects) == 1 and args.projects[0] == 'all':
      # If 'all' is specified, get all projects from the projects directory.
      projects_to_analyse = [
          p for p in os.listdir('projects')
          if os.path.isfile(os.path.join('projects', p, 'run_tests.sh'))
      ]
    else:
      projects_to_analyse = args.projects
    for project in projects_to_analyse:
      logger.info('%s checking run_tests', project)
      check_test(project, args.sanitizer, args.container_output,
                 args.run_full_cache_replay)
  if args.command == 'check-replay-script':
    check_cached_replay(args.project, args.sanitizer)
  if args.command == 'check-replay-script-integrity':
    check_cached_replay(args.project, args.sanitizer, integrity_test=True)
  if args.command == 'build-cached-image':
    build_cached_project(args.project,
                         sanitizer=args.sanitizer,
                         container_output=args.container_output)
  if args.command == 'autogen-tests':
    autogen_projects(args.apply_filtering, args.max_projects_to_try,
                     args.container_output, args.projects)
  if args.command == 'build-many-caches':
    for project in args.projects:
      logger.info('Building cached project: %s', project)
      check_cached_replay(project,
                          sanitizer=args.sanitizer,
                          container_output=args.container_output,
                          silent_replays=args.silent_replays)
  if args.command == 'extract-test-coverage':
    extract_test_coverage(args.project)


if __name__ == '__main__':
  main()
