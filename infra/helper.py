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

GLOBAL_ARGS = None

def main():
  os.chdir(OSSFUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  parser.add_argument(
      '--nopull', default=False, action='store_const', const=True,
      help='do not specify --pull while building an image')
  parser.add_argument(
      'command',
      help='One of: generate, build_image, build_fuzzers, run_fuzzer, coverage, reproduce, shell',
      nargs=argparse.REMAINDER)
  global GLOBAL_ARGS
  GLOBAL_ARGS = args = parser.parse_args()

  if not args.command:
    parser.print_help()
    return 1

  if args.command[0] == 'generate':
    return generate(args.command[1:])
  elif args.command[0] == 'build_image':
    return build_image(args.command[1:])
  elif args.command[0] == 'build_fuzzers':
    return build_fuzzers(args.command[1:])
  elif args.command[0] == 'run_fuzzer':
    return run_fuzzer(args.command[1:])
  elif args.command[0] == 'coverage':
    return coverage(args.command[1:])
  elif args.command[0] == 'reproduce':
    return reproduce(args.command[1:])
  elif args.command[0] == 'shell':
    return shell(args.command[1:])
  else:
    print('Unrecognised command!', file=sys.stderr)
    return 1

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
                      choices=['libfuzzer', 'afl'])


def _add_sanitizer_args(parser):
  """Add common sanitizer args."""
  parser.add_argument('--sanitizer', default='address',
                      choices=['address', 'memory', 'undefined'])


def _build_image(image_name):
  """Build image."""

  if _is_base_image(image_name):
    dockerfile_dir = os.path.join('infra', 'base-images', image_name)
  else:
    if not _check_project_exists(image_name):
      return False

    dockerfile_dir = os.path.join('projects', image_name)


  build_args = []
  if not GLOBAL_ARGS.nopull:
      build_args += ['--pull']
  build_args += ['-t', 'ossfuzz/%s' % image_name, dockerfile_dir ]

  command = [ 'docker', 'build' ] + build_args
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker build failed.', file=sys.stderr)
    return False

  return True


def build_image(build_args):
  """Build docker image."""
  parser = argparse.ArgumentParser('helper.py build_image')
  parser.add_argument('project_name')
  args = parser.parse_args(build_args)

  if _build_image(args.project_name):
    return 0

  return 1


def build_fuzzers(build_args):
  """Build fuzzers."""
  parser = argparse.ArgumentParser('helper.py build_fuzzers')
  _add_engine_args(parser)
  _add_sanitizer_args(parser)
  parser.add_argument('-e', action='append', help="set environment variable e.g. VAR=value")
  parser.add_argument('project_name')
  parser.add_argument('source_path', help='path of local source',
                      nargs='?')
  args = parser.parse_args(build_args)
  project_name = args.project_name

  if not _build_image(args.project_name):
    return 1

  env = [
      'BUILD_UID=%d' % os.getuid(),
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
      '-t', 'ossfuzz/%s' % project_name
  ]

  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('fuzzers build failed.', file=sys.stderr)
    return 1

  return 0


def run_fuzzer(run_args):
  """Runs a fuzzer in the container."""
  parser = argparse.ArgumentParser('helper.py run_fuzzer')
  _add_engine_args(parser)

  parser.add_argument('project_name', help='name of the project')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                      nargs=argparse.REMAINDER)
  args = parser.parse_args(run_args)

  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  if not _build_image('base-runner'):
    return 1

  env = ['FUZZING_ENGINE=' + args.engine]

  command = [
      'docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE',
  ] + sum([['-e', v] for v in env], []) + [
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-t', 'ossfuzz/base-runner',
      'run_fuzzer',
      args.fuzzer_name,
  ] + args.fuzzer_args

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


def coverage(run_args):
  """Runs a fuzzer in the container."""
  parser = argparse.ArgumentParser('helper.py coverage')
  parser.add_argument('--run_time', default=60,
                      help='time in seconds to run fuzzer')
  parser.add_argument('project_name', help='name of the project')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                      nargs=argparse.REMAINDER)
  args = parser.parse_args(run_args)

  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  if not _build_image('base-runner'):
    return 1

  temp_dir = tempfile.mkdtemp()

  command = [
      'docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE',
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/cov' % temp_dir,
      '-w', '/cov',
      '-t', 'ossfuzz/base-runner',
      '/out/%s' % args.fuzzer_name,
      '-dump_coverage=1',
      '-max_total_time=%s' % args.run_time
  ] + args.fuzzer_args

  print('Running:', _get_command_string(command))
  print('This may take a while (running your fuzzer for %d seconds)...' %
        args.run_time)
  with open(os.devnull, 'w') as f:
    pipe = subprocess.Popen(command, stdout=f, stderr=subprocess.STDOUT)
    pipe.communicate()

  command = [
        'docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE',
        '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
        '-v', '%s:/cov' % temp_dir,
        '-w', '/cov',
        '-p', '8001:8001',
        '-t', 'ossfuzz/%s' % args.project_name,
        'coverage_report', '/out/%s' % args.fuzzer_name,
  ]

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


def reproduce(run_args):
  """Reproduces a testcase in the container."""
  parser = argparse.ArgumentParser('helper.py reproduce')
  parser.add_argument('project_name', help='name of the project')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('testcase_path', help='path of local testcase')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                      nargs=argparse.REMAINDER)
  args = parser.parse_args(run_args)

  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  if not _build_image('base-runner'):
    return 1

  command = [
      'docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE',
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
      '-v', '%s:/testcase' % _get_absolute_path(args.testcase_path),
      '-t', 'ossfuzz/base-runner',
      'reproduce',
      args.fuzzer_name,
      '-runs=100',
  ] + args.fuzzer_args

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


def generate(generate_args):
  """Generate empty project files."""
  parser = argparse.ArgumentParser('helper.py generate')
  parser.add_argument('project_name')
  args = parser.parse_args(generate_args)
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


def shell(shell_args):
  """Runs a shell within a docker image."""
  parser = argparse.ArgumentParser('helper.py shell')
  parser.add_argument('project_name', help='name of the project')
  args = parser.parse_args(shell_args)

  if not _build_image(args.project_name):
    return 1

  command = [
        'docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE',
        '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.project_name),
        '-v', '%s:/work' % os.path.join(BUILD_DIR, 'work', args.project_name),
        '-t', 'ossfuzz/%s' % args.project_name,
        '/bin/bash'
  ]
  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


if __name__ == '__main__':
  sys.exit(main())
