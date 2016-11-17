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


def main():
  os.chdir(OSSFUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  parser.add_argument(
      'command',
      help='One of: generate, build_image, build_fuzzers, run_fuzzer, coverage, shell',
      nargs=argparse.REMAINDER)
  args = parser.parse_args()

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
  elif args.command[0] == 'shell':
    return shell(args.command[1:])
  else:
    print('Unrecognised command!', file=sys.stderr)
    return 1

  return 0


def _is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def _check_target_exists(target_name):
  """Checks if a target exists."""
  if not os.path.exists(os.path.join(OSSFUZZ_DIR, 'targets', target_name)):
    print(target_name, 'does not exist', file=sys.stderr)
    return False

  return True


def _check_fuzzer_exists(target_name, fuzzer_name):
  """Checks if a fuzzer exists."""
  if not os.path.exists(os.path.join(BUILD_DIR, 'out', target_name,
                                     fuzzer_name)):
    print(fuzzer_name,
          'does not seem to exist. Please run build_fuzzers first.',
          file=sys.stderr)
    return False

  return True


def _get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(pipes.quote(part) for part in command)


def _build_image(image_name):
  """Build image."""

  if _is_base_image(image_name):
    dockerfile_dir = os.path.join('infra', 'base-images', image_name)
  else:
    if not _check_target_exists(image_name):
      return False

    dockerfile_dir = os.path.join('targets', image_name)

  command = [
        'docker', 'build', '--pull', '-t', 'ossfuzz/' + image_name,
        dockerfile_dir,
  ]
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
  parser.add_argument('target_name')
  args = parser.parse_args(build_args)

  if _build_image(args.target_name):
    return 0

  return 1


def build_fuzzers(build_args):
  """Build fuzzers."""
  parser = argparse.ArgumentParser('helper.py build_fuzzers')
  parser.add_argument('target_name')
  args = parser.parse_args(build_args)

  if not _build_image(args.target_name):
    return 1

  command = [
        'docker', 'run', '-i',
        '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.target_name),
        '-t', 'ossfuzz/' + args.target_name,
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
  parser.add_argument('target_name', help='name of the target')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                      nargs=argparse.REMAINDER)
  args = parser.parse_args(run_args)

  if not _check_target_exists(args.target_name):
    return 1

  if not _check_fuzzer_exists(args.target_name, args.fuzzer_name):
    return 1

  if not _build_image('libfuzzer-runner'):
    return 1

  command = [
      'docker', 'run', '-i',
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.target_name),
      '-t', 'ossfuzz/libfuzzer-runner',
      'run_fuzzer',
      '/out/%s' % args.fuzzer_name,
  ] + args.fuzzer_args

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()

def coverage(run_args):
  """Runs a fuzzer in the container."""
  parser = argparse.ArgumentParser('helper.py coverage')
  parser.add_argument('--run_time', default=60,
                      help='time in seconds to run fuzzer')
  parser.add_argument('target_name', help='name of the target')
  parser.add_argument('fuzzer_name', help='name of the fuzzer')
  parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                      nargs=argparse.REMAINDER)
  args = parser.parse_args(run_args)

  if not _check_target_exists(args.target_name):
    return 1

  if not _check_fuzzer_exists(args.target_name, args.fuzzer_name):
    return 1

  if not _build_image('libfuzzer-runner'):
    return 1

  temp_dir = tempfile.mkdtemp()

  command = [
      'docker', 'run', '-i',
      '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.target_name),
      '-v', '%s:/cov' % temp_dir,
      '-w', '/cov',
      '-e', 'ASAN_OPTIONS=coverage=1,detect_leaks=0',
      '-t', 'ossfuzz/libfuzzer-runner',
      '/out/%s' % args.fuzzer_name,
      '-max_total_time=%s' % args.run_time
  ] + args.fuzzer_args

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()

  command = [
        'docker', 'run', '-i',
        '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.target_name),
        '-v', '%s:/cov' % temp_dir,
        '-w', '/cov',
        '-p', '8001:8001',
        '-t', 'ossfuzz/%s' % args.target_name,
        'coverage_report', '/out/%s' % args.fuzzer_name,
  ]

  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


def generate(generate_args):
  """Generate empty target files."""
  parser = argparse.ArgumentParser('helper.py generate')
  parser.add_argument('target_name')
  args = parser.parse_args(generate_args)
  dir = os.path.join('targets', args.target_name)

  try:
    os.mkdir(dir)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise
    print(dir, 'already exists.', file=sys.stderr)
    return 1

  print('Writing new files to', dir)

  template_args = {
    'target_name' : args.target_name
    }
  with open(os.path.join(dir, 'Jenkinsfile'), 'w') as f:
    f.write(templates.JENKINS_TEMPLATE % template_args)

  with open(os.path.join(dir, 'Dockerfile'), 'w') as f:
    f.write(templates.DOCKER_TEMPLATE % template_args)

  build_sh_path = os.path.join(dir, 'build.sh')
  with open(build_sh_path, 'w') as f:
    f.write(templates.BUILD_TEMPLATE % template_args)

  targets_readme_path = os.path.join('targets', 'README.md')
  update_targets_readme(targets_readme_path, args.target_name, dir)

  os.chmod(build_sh_path, 0o755)
  return 0


def shell(shell_args):
  """Runs a shell within a docker image."""
  parser = argparse.ArgumentParser('helper.py shell')
  parser.add_argument('target_name', help='name of the target')
  args = parser.parse_args(shell_args)

  if not _build_image(args.target_name):
    return 1

  command = [
        'docker', 'run', '-i',
        '-v', '%s:/out' % os.path.join(BUILD_DIR, 'out', args.target_name),
        '-t', 'ossfuzz/' + args.target_name,
        '/bin/bash'
  ]
  print('Running:', _get_command_string(command))
  pipe = subprocess.Popen(command)
  pipe.communicate()


def update_targets_readme(readme_path, target_name, fuzzers_location):
  """Add new target name and fuzzers location to the given README.md file."""
  readme_lines = []
  with open(readme_path) as f:
    readme_lines += f.readlines()

  if not readme_lines:
    print('ERROR: empty %s file' % readme_path)
    return

  TARGETS_LIST_START_TOKEN = '| Target |'
  first_target_line_number = -1
  for i, line in enumerate(readme_lines):
    if line.startswith(TARGETS_LIST_START_TOKEN):
      first_target_line_number = i + 2
      break

  if first_target_line_number < 0:
    print('ERROR: list of targets is not found in %s file' % readme_path)
    return

  def sanitize_line(line):
    while line and not line[0] in string.ascii_letters + string.digits:
      line = line[1:]
    return line

  sanitized_lines = readme_lines[first_target_line_number : ]
  sanitized_lines = [sanitize_line(line) for line in sanitized_lines]

  position_to_insert = -1
  for i in xrange(0, len(sanitized_lines)):
    if target_name > sanitized_lines[i] and target_name < sanitized_lines[i+1]:
      position_to_insert = i + 1
      break

  if position_to_insert < 0:
    print('ERROR: please update %s file manually' % readme_path)
    return

  position_to_insert += first_target_line_number
  updated_readme_lines = readme_lines[ : position_to_insert]
  updated_readme_lines.append('| %s | [/%s](%s) |\n' % (target_name,
                                                        fuzzers_location,
                                                        target_name))
  updated_readme_lines += readme_lines[position_to_insert : ]

  with open(readme_path, 'w') as f:
    f.write(''.join(updated_readme_lines))


if __name__ == '__main__':
  sys.exit(main())
