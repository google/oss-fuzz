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
import subprocess

logger = logging.getLogger(__name__)


def _get_project_cached_named(project, sanitizer='address'):
  """Gets the name of the cached project image."""
  return f'us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/{project}-ofg-cached-{sanitizer}'


def _get_project_cached_named_local(project, sanitizer='address'):
  return f'{project}-origin-{sanitizer}'


def build_project_image(project):
  """Build OSS-Fuzz base image for a project."""
  cmd = ['docker', 'build', '-t', 'gcr.io/oss-fuzz/' + project, '.']
  subprocess.check_call(' '.join(cmd),
                        shell=True,
                        cwd=os.path.join('projects', project))


def build_cached_project(project, cleanup=True, sanitizer='address'):
  """Build cached image for a project."""
  container_name = _get_project_cached_named_local(project, sanitizer)

  # Clean up the container if it exists.
  if cleanup:
    try:
      subprocess.check_call(['docker', 'container', 'rm', '-f', container_name])
    except subprocess.CalledProcessError:
      pass

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

  logger.info('Running: [%s]', ' '.join(cmd))
  subprocess.check_call(' '.join(cmd), shell=True)

  # Save the container.
  cmd = [
      'docker', 'container', 'commit', '-c', '"ENV REPLAY_ENABLED=1"', '-c',
      '"ENV CAPTURE_REPLAY_SCRIPT=1"', container_name,
      _get_project_cached_named(project, sanitizer)
  ]
  logger.info('Saving image: [%s]', ' '.join(cmd))
  subprocess.check_call(' '.join(cmd), shell=True)


def check_cached_replay(project, sanitizer='address'):
  """Checks if a cache build succeeds and times is."""
  build_project_image(project)
  build_cached_project(project, sanitizer=sanitizer)

  # Run the cached replay script.
  cmd = [
      'docker', 'run', '--rm', '--env=SANITIZER=' + sanitizer,
      '--env=FUZZING_LANGUAGE=c++',
      '-v=' + os.getcwd() + '/build/out/' + project + '/:/out/',
      '--name=' + project + '-origin-' + sanitizer + '-replay-recached',
      _get_project_cached_named(project, sanitizer), '/bin/bash', '-c',
      '"export PATH=/ccache/bin:$PATH && rm -rf /out/* && compile"'
  ]
  start = time.time()
  subprocess.check_call(' '.join(cmd), shell=True)
  end = time.time()
  logger.info('Cached build completion time: %.2f seconds', (end - start))


def check_test(args):
  """Run the `run_tests.sh` script for a specific project. Will
    build a cached container first."""
  project = args.project
  script_path = os.path.join('projects', project, 'run_tests.sh')

  if not os.path.exists(script_path):
    logger.info('Error: The script for project "%s" does not exist at %s',
                project, script_path)
    sys.exit(1)

  # Build an OSS-Fuzz image of the project
  build_project_image(project)

  # build a cached version of the project
  build_cached_project(project, args.sanitizer)

  # Run the test script
  cmd = [
      'docker', 'run', '--rm', '-ti',
      _get_project_cached_named(project, args.sanitizer), '/bin/bash', '-c',
      '"chmod +x /src/run_tests.sh && /src/run_tests.sh"'
  ]
  start = time.time()
  subprocess.check_call(' '.join(cmd), shell=True)
  end = time.time()
  logger.info('Test completion time: %.2f seconds', (end - start))


def parse_args():
  """Parses command line arguments for the manager script."""
  parser = argparse.ArgumentParser(
      'manager.py',
      description='Chronos Mnaager: a tool for managing cached OSS-Fuzz builds.'
  )
  subparsers = parser.add_subparsers(dest='command')

  check_test_parser = subparsers.add_parser(
      'check-test', help='Checks run_test.sh for specific project.')
  check_test_parser.add_argument(
      'project',
      help='The name of the project to check (e.g., "libpng").',
  )
  check_test_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use (default: address).')

  check_replay_script_parser = subparsers.add_parser(
      'check-replay-script',
      help='Checks if the replay script works for a specific project.')

  check_replay_script_parser.add_argument(
      'project', help='The name of the project to check.')
  check_replay_script_parser.add_argument(
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

  return parser.parse_args()


def main():
  """Main"""
  logging.basicConfig(level=logging.INFO)

  args = parse_args()

  if args.command == 'check-test':
    check_test(args)
  if args.command == 'check-replay-script':
    check_cached_replay(args.project, args.sanitizer)
  if args.command == 'build-cached-image':
    build_cached_project(args.project, sanitizer=args.sanitizer)


if __name__ == '__main__':
  main()
