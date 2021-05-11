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
"""Helper script for OSS-Fuzz users. Can do common tasks like building
projects/fuzzers, running them etc."""

from __future__ import print_function
from multiprocessing.dummy import Pool as ThreadPool
import argparse
import datetime
import errno
import os
import pipes
import re
import subprocess
import sys
import templates

OSS_FUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

BASE_IMAGES = [
    'gcr.io/oss-fuzz-base/base-image',
    'gcr.io/oss-fuzz-base/base-clang',
    'gcr.io/oss-fuzz-base/base-builder',
    'gcr.io/oss-fuzz-base/base-runner',
    'gcr.io/oss-fuzz-base/base-runner-debug',
    'gcr.io/oss-fuzz-base/base-sanitizer-libs-builder',
    'gcr.io/oss-fuzz-base/msan-libs-builder',
]

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_PROJECT_NAME_LENGTH = 26

if sys.version_info[0] >= 3:
  raw_input = input  # pylint: disable=invalid-name

CORPUS_URL_FORMAT = (
    'gs://{project_name}-corpus.clusterfuzz-external.appspot.com/libFuzzer/'
    '{fuzz_target}/')
CORPUS_BACKUP_URL_FORMAT = (
    'gs://{project_name}-backup.clusterfuzz-external.appspot.com/corpus/'
    'libFuzzer/{fuzz_target}/')

PROJECT_LANGUAGE_REGEX = re.compile(r'\s*language\s*:\s*([^\s]+)')

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = ['c', 'c++', 'go', 'jvm', 'rust']

WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')

# pylint: disable=too-many-lines


def main():  # pylint: disable=too-many-branches,too-many-return-statements
  """Gets subcommand from program arguments and does it. Returns 0 on success 1
  on error."""
  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = get_parser()
  args = parse_args(parser)

  # We have different default values for `sanitizer` depending on the `engine`.
  # Some commands do not have `sanitizer` argument, so `hasattr` is necessary.
  if hasattr(args, 'sanitizer') and not args.sanitizer:
    if args.engine == 'dataflow':
      args.sanitizer = 'dataflow'
    else:
      args.sanitizer = 'address'

  if args.command == 'generate':
    result = generate(args)
  elif args.command == 'build_image':
    result = build_image(args)
  elif args.command == 'build_fuzzers':
    result = build_fuzzers(args)
  elif args.command == 'check_build':
    result = check_build(args)
  elif args.command == 'download_corpora':
    result = download_corpora(args)
  elif args.command == 'run_fuzzer':
    result = run_fuzzer(args)
  elif args.command == 'coverage':
    result = coverage(args)
  elif args.command == 'reproduce':
    result = reproduce(args)
  elif args.command == 'shell':
    result = shell(args)
  elif args.command == 'pull_images':
    result = pull_images()
  else:
    # Print help string if no arguments provided.
    parser.print_help()
    result = False
  return bool_to_retcode(result)


def bool_to_retcode(boolean):
  """Returns 0 if |boolean| is Truthy, 0 is the standard return code for a
  successful process execution. Returns 1 otherwise, indicating the process
  failed."""
  return 0 if boolean else 1


def parse_args(parser, args=None):
  """Parses |args| using |parser| and returns parsed args."""
  # Use default argument None for args so that in production, argparse does its
  # normal behavior, but unittesting is easier.
  return parser.parse_args(args)


def get_parser():  # pylint: disable=too-many-statements
  """Returns an argparse parser."""
  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  subparsers = parser.add_subparsers(dest='command')

  generate_parser = subparsers.add_parser(
      'generate', help='Generate files for new project.')
  generate_parser.add_argument('project_name')

  build_image_parser = subparsers.add_parser('build_image',
                                             help='Build an image.')
  build_image_parser.add_argument('project_name')
  build_image_parser.add_argument('--pull',
                                  action='store_true',
                                  help='Pull latest base image.')
  build_image_parser.add_argument('--no-pull',
                                  action='store_true',
                                  help='Do not pull latest base image.')

  build_fuzzers_parser = subparsers.add_parser(
      'build_fuzzers', help='Build fuzzers for a project.')
  _add_architecture_args(build_fuzzers_parser)
  _add_engine_args(build_fuzzers_parser)
  _add_sanitizer_args(build_fuzzers_parser)
  _add_environment_args(build_fuzzers_parser)
  build_fuzzers_parser.add_argument('project_name')
  build_fuzzers_parser.add_argument('source_path',
                                    help='path of local source',
                                    nargs='?')
  build_fuzzers_parser.add_argument('--clean',
                                    dest='clean',
                                    action='store_true',
                                    help='clean existing artifacts.')
  build_fuzzers_parser.add_argument('--no-clean',
                                    dest='clean',
                                    action='store_false',
                                    help='do not clean existing artifacts '
                                    '(default).')
  build_fuzzers_parser.set_defaults(clean=False)

  check_build_parser = subparsers.add_parser(
      'check_build', help='Checks that fuzzers execute without errors.')
  _add_architecture_args(check_build_parser)
  _add_engine_args(
      check_build_parser,
      choices=['libfuzzer', 'afl', 'honggfuzz', 'dataflow', 'none'])
  _add_sanitizer_args(
      check_build_parser,
      choices=['address', 'memory', 'undefined', 'dataflow', 'thread'])
  _add_environment_args(check_build_parser)
  check_build_parser.add_argument('project_name', help='name of the project')
  check_build_parser.add_argument('fuzzer_name',
                                  help='name of the fuzzer',
                                  nargs='?')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzer', help='Run a fuzzer in the emulated fuzzing environment.')
  _add_engine_args(run_fuzzer_parser)
  _add_sanitizer_args(run_fuzzer_parser)
  _add_environment_args(run_fuzzer_parser)
  run_fuzzer_parser.add_argument(
      '--corpus-dir', help='directory to store corpus for the fuzz target')
  run_fuzzer_parser.add_argument('project_name', help='name of the project')
  run_fuzzer_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  run_fuzzer_parser.add_argument('fuzzer_args',
                                 help='arguments to pass to the fuzzer',
                                 nargs=argparse.REMAINDER)

  coverage_parser = subparsers.add_parser(
      'coverage', help='Generate code coverage report for the project.')
  coverage_parser.add_argument('--no-corpus-download',
                               action='store_true',
                               help='do not download corpus backup from '
                               'OSS-Fuzz; use corpus located in '
                               'build/corpus/<project>/<fuzz_target>/')
  coverage_parser.add_argument('--port',
                               default='8008',
                               help='specify port for'
                               ' a local HTTP server rendering coverage report')
  coverage_parser.add_argument('--fuzz-target',
                               help='specify name of a fuzz '
                               'target to be run for generating coverage '
                               'report')
  coverage_parser.add_argument('--corpus-dir',
                               help='specify location of corpus'
                               ' to be used (requires --fuzz-target argument)')
  coverage_parser.add_argument('project_name', help='name of the project')
  coverage_parser.add_argument('extra_args',
                               help='additional arguments to '
                               'pass to llvm-cov utility.',
                               nargs='*')

  download_corpora_parser = subparsers.add_parser(
      'download_corpora', help='Download all corpora for a project.')
  download_corpora_parser.add_argument('--fuzz-target',
                                       help='specify name of a fuzz target')
  download_corpora_parser.add_argument('project_name',
                                       help='name of the project')

  reproduce_parser = subparsers.add_parser('reproduce',
                                           help='Reproduce a crash.')
  reproduce_parser.add_argument('--valgrind',
                                action='store_true',
                                help='run with valgrind')
  reproduce_parser.add_argument('project_name', help='name of the project')
  reproduce_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  reproduce_parser.add_argument('testcase_path', help='path of local testcase')
  reproduce_parser.add_argument('fuzzer_args',
                                help='arguments to pass to the fuzzer',
                                nargs=argparse.REMAINDER)
  _add_environment_args(reproduce_parser)

  shell_parser = subparsers.add_parser(
      'shell', help='Run /bin/bash within the builder container.')
  shell_parser.add_argument('project_name', help='name of the project')
  shell_parser.add_argument('source_path',
                            help='path of local source',
                            nargs='?')
  _add_architecture_args(shell_parser)
  _add_engine_args(shell_parser)
  _add_sanitizer_args(shell_parser)
  _add_environment_args(shell_parser)

  subparsers.add_parser('pull_images', help='Pull base images.')
  return parser


def is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def check_project_exists(project_name):
  """Checks if a project exists."""
  if not os.path.exists(_get_project_dir(project_name)):
    print(project_name, 'does not exist', file=sys.stderr)
    return False

  return True


def _check_fuzzer_exists(project_name, fuzzer_name):
  """Checks if a fuzzer exists."""
  command = ['docker', 'run', '--rm']
  command.extend(['-v', '%s:/out' % _get_out_dir(project_name)])
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


def _get_project_dir(project_name):
  """Returns path to the project."""
  return os.path.join(OSS_FUZZ_DIR, 'projects', project_name)


def get_dockerfile_path(project_name):
  """Returns path to the project Dockerfile."""
  return os.path.join(_get_project_dir(project_name), 'Dockerfile')


def _get_project_build_subdir(project_name, subdir_name):
  """Creates the |subdir_name| subdirectory of the |project_name| subdirectory
  in |BUILD_DIR| and returns its path."""
  directory = os.path.join(BUILD_DIR, subdir_name, project_name)
  if not os.path.exists(directory):
    os.makedirs(directory)

  return directory


def _get_corpus_dir(project_name=''):
  """Creates and returns path to /corpus directory for the given project (if
  specified)."""
  return _get_project_build_subdir(project_name, 'corpus')


def _get_out_dir(project_name=''):
  """Creates and returns path to /out directory for the given project (if
  specified)."""
  return _get_project_build_subdir(project_name, 'out')


def _get_work_dir(project_name=''):
  """Creates and returns path to /work directory for the given project (if
  specified)."""
  return _get_project_build_subdir(project_name, 'work')


def _get_project_language(project_name):
  """Returns project language."""
  project_yaml_path = os.path.join(OSS_FUZZ_DIR, 'projects', project_name,
                                   'project.yaml')
  with open(project_yaml_path) as file_handle:
    content = file_handle.read()
    for line in content.splitlines():
      match = PROJECT_LANGUAGE_REGEX.match(line)
      if match:
        return match.group(1)

  return None


def _add_architecture_args(parser, choices=('x86_64', 'i386')):
  """Adds common architecture args."""
  parser.add_argument('--architecture', default='x86_64', choices=choices)


def _add_engine_args(parser,
                     choices=('libfuzzer', 'afl', 'honggfuzz', 'dataflow',
                              'none')):
  """Adds common engine args."""
  parser.add_argument('--engine', default='libfuzzer', choices=choices)


def _add_sanitizer_args(parser,
                        choices=('address', 'memory', 'undefined', 'coverage',
                                 'dataflow', 'thread')):
  """Adds common sanitizer args."""
  parser.add_argument(
      '--sanitizer',
      default=None,
      choices=choices,
      help='the default is "address"; "dataflow" for "dataflow" engine')


def _add_environment_args(parser):
  """Adds common environment args."""
  parser.add_argument('-e',
                      action='append',
                      help="set environment variable e.g. VAR=value")


def build_image_impl(image_name, no_cache=False, pull=False):
  """Builds image."""
  proj_is_base_image = is_base_image(image_name)
  if proj_is_base_image:
    image_project = 'oss-fuzz-base'
    dockerfile_dir = os.path.join('infra', 'base-images', image_name)
  else:
    image_project = 'oss-fuzz'
    if not check_project_exists(image_name):
      return False
    dockerfile_dir = os.path.join('projects', image_name)

  if pull and not pull_images():
    return False

  build_args = []
  if no_cache:
    build_args.append('--no-cache')

  build_args += [
      '-t', 'gcr.io/%s/%s' % (image_project, image_name), dockerfile_dir
  ]
  return docker_build(build_args)


def _env_to_docker_args(env_list):
  """Turns envirnoment variable list into docker arguments."""
  return sum([['-e', v] for v in env_list], [])


def workdir_from_lines(lines, default='/src'):
  """Gets the WORKDIR from the given lines."""
  for line in reversed(lines):  # reversed to get last WORKDIR.
    match = re.match(WORKDIR_REGEX, line)
    if match:
      workdir = match.group(1)
      workdir = workdir.replace('$SRC', '/src')

      if not os.path.isabs(workdir):
        workdir = os.path.join('/src', workdir)

      return os.path.normpath(workdir)

  return default


def _workdir_from_dockerfile(project_name):
  """Parses WORKDIR from the Dockerfile for the given project."""
  dockerfile_path = get_dockerfile_path(project_name)

  with open(dockerfile_path) as file_handle:
    lines = file_handle.readlines()

  return workdir_from_lines(lines, default=os.path.join('/src', project_name))


def docker_run(run_args, print_output=True):
  """Calls `docker run`."""
  command = ['docker', 'run', '--rm', '--privileged']

  # Support environments with a TTY.
  if sys.stdin.isatty():
    command.append('-i')

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


def docker_build(build_args):
  """Calls `docker build`."""
  command = ['docker', 'build']
  command.extend(build_args)
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker build failed.', file=sys.stderr)
    return False

  return True


def docker_pull(image):
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
  """Builds docker image."""
  if args.pull and args.no_pull:
    print('Incompatible arguments --pull and --no-pull.')
    return False

  if args.pull:
    pull = True
  elif args.no_pull:
    pull = False
  else:
    y_or_n = raw_input('Pull latest base images (compiler/runtime)? (y/N): ')
    pull = y_or_n.lower() == 'y'

  if pull:
    print('Pulling latest base images...')
  else:
    print('Using cached base images...')

  # If build_image is called explicitly, don't use cache.
  if build_image_impl(args.project_name, no_cache=True, pull=pull):
    return True

  return False


def build_fuzzers_impl(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    project_name,
    clean,
    engine,
    sanitizer,
    architecture,
    env_to_add,
    source_path,
    no_cache=False,
    mount_location=None):
  """Builds fuzzers."""
  if not build_image_impl(project_name, no_cache=no_cache):
    return False

  project_out_dir = _get_out_dir(project_name)
  project_work_dir = _get_work_dir(project_name)
  project_language = _get_project_language(project_name)
  if not project_language:
    print('WARNING: language not specified in project.yaml. Build may fail.')

  if clean:
    print('Cleaning existing build artifacts.')

    # Clean old and possibly conflicting artifacts in project's out directory.
    docker_run([
        '-v',
        '%s:/out' % project_out_dir, '-t',
        'gcr.io/oss-fuzz/%s' % project_name, '/bin/bash', '-c', 'rm -rf /out/*'
    ])

    docker_run([
        '-v',
        '%s:/work' % project_work_dir, '-t',
        'gcr.io/oss-fuzz/%s' % project_name, '/bin/bash', '-c', 'rm -rf /work/*'
    ])

  else:
    print('Keeping existing build artifacts as-is (if any).')
  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer,
      'ARCHITECTURE=' + architecture,
  ]

  _add_oss_fuzz_ci_if_needed(env)

  if project_language:
    env.append('FUZZING_LANGUAGE=' + project_language)

  if env_to_add:
    env += env_to_add

  # Copy instrumented libraries.
  if sanitizer == 'memory':
    docker_run([
        '-v',
        '%s:/work' % project_work_dir, 'gcr.io/oss-fuzz-base/msan-libs-builder',
        'bash', '-c', 'cp -r /msan /work'
    ])
    env.append('MSAN_LIBS_PATH=' + '/work/msan')

  command = ['--cap-add', 'SYS_PTRACE'] + _env_to_docker_args(env)
  if source_path:
    workdir = _workdir_from_dockerfile(project_name)
    if mount_location:
      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), mount_location),
      ]
    else:
      if workdir == '/src':
        print('Cannot use local checkout with "WORKDIR: /src".',
              file=sys.stderr)
        return False

      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), workdir),
      ]

  command += [
      '-v',
      '%s:/out' % project_out_dir, '-v',
      '%s:/work' % project_work_dir, '-t',
      'gcr.io/oss-fuzz/%s' % project_name
  ]

  result = docker_run(command)
  if not result:
    print('Building fuzzers failed.', file=sys.stderr)
    return False

  # Patch MSan builds to use instrumented shared libraries.
  if sanitizer == 'memory':
    docker_run([
        '-v',
        '%s:/out' % project_out_dir, '-v',
        '%s:/work' % project_work_dir
    ] + _env_to_docker_args(env) + [
        'gcr.io/oss-fuzz-base/base-sanitizer-libs-builder', 'patch_build.py',
        '/out'
    ])

  return True


def build_fuzzers(args):
  """Builds fuzzers."""
  return build_fuzzers_impl(args.project_name, args.clean, args.engine,
                            args.sanitizer, args.architecture, args.e,
                            args.source_path)


def _add_oss_fuzz_ci_if_needed(env):
  """Adds value of |OSS_FUZZ_CI| environment variable to |env| if it is set."""
  oss_fuzz_ci = os.getenv('OSS_FUZZ_CI')
  if oss_fuzz_ci:
    env.append('OSS_FUZZ_CI=' + oss_fuzz_ci)


def check_build(args):
  """Checks that fuzzers in the container execute without errors."""
  if not check_project_exists(args.project_name):
    return False

  if (args.fuzzer_name and
      not _check_fuzzer_exists(args.project_name, args.fuzzer_name)):
    return False

  fuzzing_language = _get_project_language(args.project_name)
  if fuzzing_language is None:
    print('WARNING: language not specified in project.yaml. Defaulting to C++.')
    fuzzing_language = 'c++'

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'ARCHITECTURE=' + args.architecture,
      'FUZZING_LANGUAGE=' + fuzzing_language,
  ]
  _add_oss_fuzz_ci_if_needed(env)
  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env) + [
      '-v',
      '%s:/out' % _get_out_dir(args.project_name), '-t',
      'gcr.io/oss-fuzz-base/base-runner'
  ]

  if args.fuzzer_name:
    run_args += ['test_one.py', args.fuzzer_name]
  else:
    run_args.append('test_all.py')

  result = docker_run(run_args)
  if result:
    print('Check build passed.')
  else:
    print('Check build failed.')

  return result


def _get_fuzz_targets(project_name):
  """Returns names of fuzz targest build in the project's /out directory."""
  fuzz_targets = []
  for name in os.listdir(_get_out_dir(project_name)):
    if name.startswith('afl-'):
      continue

    path = os.path.join(_get_out_dir(project_name), name)
    if os.path.isfile(path) and os.access(path, os.X_OK):
      fuzz_targets.append(name)

  return fuzz_targets


def _get_latest_corpus(project_name, fuzz_target, base_corpus_dir):
  """Downloads the latest corpus for the given fuzz target."""
  corpus_dir = os.path.join(base_corpus_dir, fuzz_target)
  if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)

  if not fuzz_target.startswith(project_name + '_'):
    fuzz_target = '%s_%s' % (project_name, fuzz_target)

  corpus_backup_url = CORPUS_BACKUP_URL_FORMAT.format(project_name=project_name,
                                                      fuzz_target=fuzz_target)
  command = ['gsutil', 'ls', corpus_backup_url]

  # Don't capture stderr. We want it to print in real time, in case gsutil is
  # asking for two-factor authentication.
  corpus_listing = subprocess.Popen(command, stdout=subprocess.PIPE)
  output, _ = corpus_listing.communicate()

  # Some fuzz targets (e.g. new ones) may not have corpus yet, just skip those.
  if corpus_listing.returncode:
    print('WARNING: corpus for {0} not found:\n'.format(fuzz_target),
          file=sys.stderr)
    return

  if output:
    latest_backup_url = output.splitlines()[-1]
    archive_path = corpus_dir + '.zip'
    command = ['gsutil', '-q', 'cp', latest_backup_url, archive_path]
    subprocess.check_call(command)

    command = ['unzip', '-q', '-o', archive_path, '-d', corpus_dir]
    subprocess.check_call(command)
    os.remove(archive_path)
  else:
    # Sync the working corpus copy if a minimized backup is not available.
    corpus_url = CORPUS_URL_FORMAT.format(project_name=project_name,
                                          fuzz_target=fuzz_target)
    command = ['gsutil', '-m', '-q', 'rsync', '-R', corpus_url, corpus_dir]
    subprocess.check_call(command)


def download_corpora(args):
  """Downloads most recent corpora from GCS for the given project."""
  if not check_project_exists(args.project_name):
    return False

  try:
    with open(os.devnull, 'w') as stdout:
      subprocess.check_call(['gsutil', '--version'], stdout=stdout)
  except OSError:
    print(
        'ERROR: gsutil not found. Please install it from '
        'https://cloud.google.com/storage/docs/gsutil_install',
        file=sys.stderr)
    return False

  if args.fuzz_target:
    fuzz_targets = [args.fuzz_target]
  else:
    fuzz_targets = _get_fuzz_targets(args.project_name)

  corpus_dir = _get_corpus_dir(args.project_name)
  if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)

  def _download_for_single_target(fuzz_target):
    try:
      _get_latest_corpus(args.project_name, fuzz_target, corpus_dir)
      return True
    except Exception as error:  # pylint:disable=broad-except
      print('ERROR: corpus download for %s failed: %s' %
            (fuzz_target, str(error)),
            file=sys.stderr)
      return False

  print('Downloading corpora for %s project to %s' %
        (args.project_name, corpus_dir))
  thread_pool = ThreadPool()
  return all(thread_pool.map(_download_for_single_target, fuzz_targets))


def coverage(args):
  """Generates code coverage using clang source based code coverage."""
  if args.corpus_dir and not args.fuzz_target:
    print(
        'ERROR: --corpus-dir requires specifying a particular fuzz target '
        'using --fuzz-target',
        file=sys.stderr)
    return False

  if not check_project_exists(args.project_name):
    return False

  project_language = _get_project_language(args.project_name)
  if project_language not in LANGUAGES_WITH_COVERAGE_SUPPORT:
    print(
        'ERROR: Project is written in %s, coverage for it is not supported yet.'
        % project_language,
        file=sys.stderr)
    return False

  if not args.no_corpus_download and not args.corpus_dir:
    if not download_corpora(args):
      return False

  env = [
      'FUZZING_ENGINE=libfuzzer',
      'FUZZING_LANGUAGE=%s' % project_language,
      'PROJECT=%s' % args.project_name,
      'SANITIZER=coverage',
      'HTTP_PORT=%s' % args.port,
      'COVERAGE_EXTRA_ARGS=%s' % ' '.join(args.extra_args),
  ]

  run_args = _env_to_docker_args(env)

  if args.port:
    run_args.extend([
        '-p',
        '%s:%s' % (args.port, args.port),
    ])

  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      print('ERROR: the path provided in --corpus-dir argument does not exist',
            file=sys.stderr)
      return False
    corpus_dir = os.path.realpath(args.corpus_dir)
    run_args.extend(['-v', '%s:/corpus/%s' % (corpus_dir, args.fuzz_target)])
  else:
    run_args.extend(['-v', '%s:/corpus' % _get_corpus_dir(args.project_name)])

  run_args.extend([
      '-v',
      '%s:/out' % _get_out_dir(args.project_name),
      '-t',
      'gcr.io/oss-fuzz-base/base-runner',
  ])

  run_args.append('coverage')
  if args.fuzz_target:
    run_args.append(args.fuzz_target)

  result = docker_run(run_args)
  if result:
    print('Successfully generated clang code coverage report.')
  else:
    print('Failed to generate clang code coverage report.')

  return result


def run_fuzzer(args):
  """Runs a fuzzer in the container."""
  if not check_project_exists(args.project_name):
    return False

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return False

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'RUN_FUZZER_MODE=interactive',
  ]

  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env)

  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      print('ERROR: the path provided in --corpus-dir argument does not exist',
            file=sys.stderr)
      return False
    corpus_dir = os.path.realpath(args.corpus_dir)
    run_args.extend([
        '-v',
        '{corpus_dir}:/tmp/{fuzzer}_corpus'.format(corpus_dir=corpus_dir,
                                                   fuzzer=args.fuzzer_name)
    ])

  run_args.extend([
      '-v',
      '%s:/out' % _get_out_dir(args.project_name),
      '-t',
      'gcr.io/oss-fuzz-base/base-runner',
      'run_fuzzer',
      args.fuzzer_name,
  ] + args.fuzzer_args)

  return docker_run(run_args)


def reproduce(args):
  """Reproduces a specific test case from a specific project."""
  return reproduce_impl(args.project_name, args.fuzzer_name, args.valgrind,
                        args.e, args.fuzzer_args, args.testcase_path)


def reproduce_impl(  # pylint: disable=too-many-arguments
    project_name,
    fuzzer_name,
    valgrind,
    env_to_add,
    fuzzer_args,
    testcase_path,
    run_function=docker_run,
    err_result=False):
  """Reproduces a testcase in the container."""
  if not check_project_exists(project_name):
    return err_result

  if not _check_fuzzer_exists(project_name, fuzzer_name):
    return err_result

  debugger = ''
  env = []
  image_name = 'base-runner'

  if valgrind:
    debugger = 'valgrind --tool=memcheck --track-origins=yes --leak-check=full'

  if debugger:
    image_name = 'base-runner-debug'
    env += ['DEBUGGER=' + debugger]

  if env_to_add:
    env += env_to_add

  run_args = _env_to_docker_args(env) + [
      '-v',
      '%s:/out' % _get_out_dir(project_name),
      '-v',
      '%s:/testcase' % _get_absolute_path(testcase_path),
      '-t',
      'gcr.io/oss-fuzz-base/%s' % image_name,
      'reproduce',
      fuzzer_name,
      '-runs=100',
  ] + fuzzer_args

  return run_function(run_args)


def generate(args):
  """Generates empty project files."""
  if len(args.project_name) > MAX_PROJECT_NAME_LENGTH:
    print('Project name needs to be less than or equal to %d characters.' %
          MAX_PROJECT_NAME_LENGTH,
          file=sys.stderr)
    return False

  if not VALID_PROJECT_NAME_REGEX.match(args.project_name):
    print('Invalid project name.', file=sys.stderr)
    return False

  directory = os.path.join('projects', args.project_name)

  try:
    os.mkdir(directory)
  except OSError as error:
    if error.errno != errno.EEXIST:
      raise
    print(directory, 'already exists.', file=sys.stderr)
    return False

  print('Writing new files to', directory)

  template_args = {
      'project_name': args.project_name,
      'year': datetime.datetime.now().year
  }
  with open(os.path.join(directory, 'project.yaml'), 'w') as file_handle:
    file_handle.write(templates.PROJECT_YAML_TEMPLATE % template_args)

  with open(os.path.join(directory, 'Dockerfile'), 'w') as file_handle:
    file_handle.write(templates.DOCKER_TEMPLATE % template_args)

  build_sh_path = os.path.join(directory, 'build.sh')
  with open(build_sh_path, 'w') as file_handle:
    file_handle.write(templates.BUILD_TEMPLATE % template_args)

  os.chmod(build_sh_path, 0o755)
  return True


def shell(args):
  """Runs a shell within a docker image."""
  if not build_image_impl(args.project_name):
    return False

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'ARCHITECTURE=' + args.architecture,
  ]

  if args.project_name != 'base-runner-debug':
    env.append('FUZZING_LANGUAGE=' + _get_project_language(args.project_name))

  if args.e:
    env += args.e

  if is_base_image(args.project_name):
    image_project = 'oss-fuzz-base'
    out_dir = _get_out_dir()
  else:
    image_project = 'oss-fuzz'
    out_dir = _get_out_dir(args.project_name)

  run_args = _env_to_docker_args(env)
  if args.source_path:
    run_args.extend([
        '-v',
        '%s:%s' % (_get_absolute_path(args.source_path), '/src'),
    ])

  run_args.extend([
      '-v',
      '%s:/out' % out_dir, '-v',
      '%s:/work' % _get_work_dir(args.project_name), '-t',
      'gcr.io/%s/%s' % (image_project, args.project_name), '/bin/bash'
  ])

  docker_run(run_args)
  return True


def pull_images():
  """Pulls base images."""
  for base_image in BASE_IMAGES:
    if not docker_pull(base_image):
      return False

  return True


if __name__ == '__main__':
  sys.exit(main())
