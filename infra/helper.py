#!/usr/bin/env python
# Copyright 2016 Google Inc.
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

from __future__ import print_function
import argparse
import errno
import os
import pipes
import re
import shutil
import string
import subprocess
import sys
import tempfile
import templates
import time

OSSFUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSSFUZZ_DIR, 'build')

BASE_IMAGES = [
    'gcr.io/oss-fuzz-base/base-image',
    'gcr.io/oss-fuzz-base/base-clang',
    'gcr.io/oss-fuzz-base/base-builder',
    'gcr.io/oss-fuzz-base/base-runner',
    'gcr.io/oss-fuzz-base/base-runner-debug',
]

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')


def main():
  os.chdir(OSSFUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  subparsers = parser.add_subparsers(dest='command')

  generate_parser = subparsers.add_parser(
      'generate', help='Generate files for new project.')
  generate_parser.add_argument('project_name')

  build_image_parser = subparsers.add_parser(
      'build_image', help='Build an image.')
  build_image_parser.add_argument('project_name')
  build_image_parser.add_argument('--pull', action='store_true',
                                  help='Pull latest base image.')

  build_fuzzers_parser = subparsers.add_parser(
      'build_fuzzers', help='Build fuzzers for a project.')
  _add_engine_args(build_fuzzers_parser)
  _add_sanitizer_args(build_fuzzers_parser)
  _add_environment_args(build_fuzzers_parser)
  build_fuzzers_parser.add_argument('project_name')
  build_fuzzers_parser.add_argument('source_path', help='path of local source',
                                    nargs='?')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzer', help='Run a fuzzer.')
  _add_engine_args(run_fuzzer_parser)
  run_fuzzer_parser.add_argument('project_name', help='name of the project')
  run_fuzzer_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  run_fuzzer_parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                                 nargs=argparse.REMAINDER)

  coverage_parser = subparsers.add_parser(
      'coverage', help='Run a fuzzer for a while and generate coverage.')
  coverage_parser.add_argument('--run_time', default=60,
                      help='time in seconds to run fuzzer')
  coverage_parser.add_argument('project_name', help='name of the project')
  coverage_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  coverage_parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                               nargs=argparse.REMAINDER)

  reproduce_parser = subparsers.add_parser(
      'reproduce', help='Reproduce a crash.')
  reproduce_parser.add_argument('--valgrind', action='store_true',
                       help='run with valgrind')
  reproduce_parser.add_argument('project_name', help='name of the project')
  reproduce_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  reproduce_parser.add_argument('testcase_path', help='path of local testcase')
  reproduce_parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                                nargs=argparse.REMAINDER)

  shell_parser = subparsers.add_parser(
      'shell', help='Run /bin/bash in an image.')
  shell_parser.add_argument('project_name', help='name of the project')
  _add_engine_args(shell_parser)
  _add_sanitizer_args(shell_parser)
  _add_environment_args(shell_parser)

  pull_images_parser = subparsers.add_parser('pull_images',
                                             help='Pull base images.')

  args = parser.parse_args()
  if args.command == 'generate':
    return generate(args)
  elif args.command == 'build_image':
    return build_image(args)
  elif args.command == 'build_fuzzers':
    return build_fuzzers(args)
  elif args.command == 'run_fuzzer':
    return run_fuzzer(args)
  elif args.command == 'coverage':
    return coverage(args)
  elif args.command == 'reproduce':
    return reproduce(args)
  elif args.command == 'shell':
    return shell(args)
  elif args.command == 'pull_images':
    return pull_images(args)

  return 0


def _is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def _check_project_exists(project_name):
  """Checks if a project exists."""
  if not os.path.exists(os.path.join(OSSFUZZ_DIR, 'projects', project_name)):
    print(project_name, 'does not exist', file=sys.stderr)
    return False

  return True


def _check_fuzzer_exists(project_name, fuzzer_name):
  """Checks if a fuzzer exists."""
  command = ['docker', 'run', '--rm']
  command.extend(['-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', project_name)])
  command.append('ubuntu:16.04')

  command.extend(['/bin/bash', '-c', 'test -f /out/%s' % fuzzer_name])

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print(fuzzer_name,
          'does not seem to exist. Please run build_fuzzers first.',
          file=sys.stderr)
    return False

  return True


def _get_absolute_path(path):
  """Returns absolute path with user expansion."""
  return os.path.abspath(os.path.expanduser(path))


def _get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(pipes.quote(part) for part in command)


def _add_engine_args(parser):
  """Add common engine args."""
  parser.add_argument('--engine', default='libfuzzer',
                      choices=['libfuzzer', 'afl', 'honggfuzz'])


def _add_sanitizer_args(parser):
  """Add common sanitizer args."""
  parser.add_argument('--sanitizer', default='address',
                      choices=['address', 'memory', 'profile', 'undefined'])


def _add_environment_args(parser):
  """Add common environment args."""
  parser.add_argument('-e', action='append',
                      help="set environment variable e.g. VAR=value")


def _build_image(image_name, no_cache=False, pull=False):
  """Build image."""

  is_base_image = _is_base_image(image_name)
  if is_base_image:
    image_project = 'oss-fuzz-base'
    dockerfile_dir = os.path.join('infra', 'base-images', image_name)
  else:
    image_project = 'oss-fuzz'
    if not _check_project_exists(image_name):
      return False

    dockerfile_dir = os.path.join('projects', image_name)

  build_args = []
  if no_cache:
    build_args.append('--no-cache')

  build_args += ['-t', 'gcr.io/%s/%s' % (image_project, image_name), dockerfile_dir]

  return docker_build(build_args, pull=pull)


def docker_run(run_args, print_output=True):
  """Call `docker run`."""
  command = ['docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE']
  command.extend(run_args)

  print('Running:', _get_command_string(command))
  stdout = None
  if not print_output:
    stdout = open(os.devnull, 'w')

  try:
    subprocess.check_call(command, stdout=stdout, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError:
    return False

  return True


def docker_build(build_args, pull=False):
  """Call `docker build`."""
  command = ['docker', 'build']
  if pull:
    command.append('--pull')

  command.extend(build_args)
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker build failed.', file=sys.stderr)
    return False

  return True


def docker_pull(image, pull=False):
  """Call `docker pull`."""
  command = ['docker', 'pull', image]
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker pull failed.', file=sys.stderr)
    return False

  return True


def build_image(args):
  """Build docker image."""
  pull = args.pull
  if not pull:
    y_or_n = raw_input('Pull latest base images (compiler/runtime)? (y/N): ')
    pull = y_or_n.lower() == 'y'

  if pull:
    print('Pulling latest base images...')
  else:
    print('Using cached base images...')

  # If build_image is called explicitly, don't use cache.
  if _build_image(args.project_name, no_cache=True, pull=pull):
    return 0

  return 1


def build_fuzzers(args):
  """Build fuzzers."""
  project_name = args.project_name

  if not _build_image(args.project_name):
    return 1

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer
  ]

  if args.e:
    env += args.e

  command = (
      ['docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE'] +
      sum([['-e', v] for v in env], [])
  )
  if args.source_path:
    command += [
        '-v',
        '%s:/src/%s' % (_get_absolute_path(args.source_path), args.project_name)
    ]
  command += [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', project_name),
      '-v', '%s:/work' % os.path.join(BUILD_DIR, 'work', project_name),
      '-t', 'gcr.io/oss-fuzz/%s' % project_name
  ]

  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('fuzzers build failed.', file=sys.stderr)
    return 1

  return 0


def run_fuzzer(args):
  """Runs a fuzzer in the container."""
  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  env = ['FUZZING_ENGINE=' + args.engine]

  run_args = sum([['-e', v] for v in env], []) + [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-t', 'gcr.io/oss-fuzz-base/base-runner',
      'run_fuzzer',
      args.fuzzer_name,
  ] + args.fuzzer_args

  docker_run(run_args)


def coverage(args):
  """Runs a fuzzer in the container."""
  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  temp_dir = tempfile.mkdtemp()

  run_args = [
      '-e', 'FUZZING_ENGINE=libfuzzer',
      '-e', 'ASAN_OPTIONS=coverage_dir=/cov',
      '-e', 'MSAN_OPTIONS=coverage_dir=/cov',
      '-e', 'UBSAN_OPTIONS=coverage_dir=/cov',
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/cov' % temp_dir,
      '-w', '/cov',
      '-t', 'gcr.io/oss-fuzz-base/base-runner',
      'run_fuzzer',
      args.fuzzer_name,
      '-dump_coverage=1',
      '-max_total_time=%s' % args.run_time
  ] + args.fuzzer_args

  print('This may take a while (running your fuzzer for %s seconds)...' %
        args.run_time)
  docker_run(run_args, print_output=False)

  run_args = [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/cov' % temp_dir,
      '-w', '/cov',
      '-p', '8001:8001',
      '-t', 'gcr.io/oss-fuzz/%s' % args.project_name,
      'coverage_report', '/out/%s' % args.fuzzer_name,
  ]

  docker_run(run_args)


def reproduce(args):
  """Reproduces a testcase in the container."""
  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  debugger = ''
  env = []
  image_name = 'base-runner'

  if args.valgrind:
    debugger = 'valgrind --tool=memcheck --track-origins=yes --leak-check=full'

  if debugger:
    image_name = 'base-runner-debug'
    env += ['DEBUGGER=' + debugger]

  run_args = sum([['-e', v] for v in env], []) + [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/testcase' % _get_absolute_path(args.testcase_path),
      '-t', 'gcr.io/oss-fuzz-base/%s' % image_name,
      'reproduce',
      args.fuzzer_name,
      '-runs=100',
  ] + args.fuzzer_args

  docker_run(run_args)


def generate(args):
  """Generate empty project files."""
  if not VALID_PROJECT_NAME_REGEX.match(args.project_name):
    print('Invalid project name.', file=sys.stderr)
    return 1

  dir = os.path.join('projects', args.project_name)

  try:
    os.mkdir(dir)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise
    print(dir, 'already exists.', file=sys.stderr)
    return 1

  print('Writing new files to', dir)

  template_args = {
    'project_name' : args.project_name
  }
  with open(os.path.join(dir, 'project.yaml'), 'w') as f:
    f.write(templates.PROJECT_YAML_TEMPLATE % template_args)

  with open(os.path.join(dir, 'Dockerfile'), 'w') as f:
    f.write(templates.DOCKER_TEMPLATE % template_args)

  build_sh_path = os.path.join(dir, 'build.sh')
  with open(build_sh_path, 'w') as f:
    f.write(templates.BUILD_TEMPLATE % template_args)

  os.chmod(build_sh_path, 0o755)
  return 0


def shell(args):
  """Runs a shell within a docker image."""
  if not _build_image(args.project_name):
    return 1

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer
  ]

  if args.e:
    env += args.e

  run_args = sum([['-e', v] for v in env], []) + [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/work' % os.path.join(BUILD_DIR, 'work', args.project_name),
      '-t', 'gcr.io/oss-fuzz/%s' % args.project_name,
      '/bin/bash'
  ]

  docker_run(run_args)
  return 0


def pull_images(args):
  """Pull base images."""
  for base_image in BASE_IMAGES:
    if not docker_pull(base_image):
      return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
