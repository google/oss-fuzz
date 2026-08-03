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
import subprocess

# Call from the core OSS-Fuzz repository:
# PYTHONPATH=$PYTHONPATH:$PWD/infra python3 -m chronos.manager check-tests json-c
from chronos import integrity_validator_check_replay
from chronos import integrity_validator_run_tests
import common_utils

logger = logging.getLogger(__name__)


def _get_oss_fuzz_root():
  """Gets the root directory of the OSS-Fuzz repository."""
  return os.path.abspath(
      os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))


def _get_project_cached_named(project: common_utils.Project,
                              sanitizer='address'):
  """Gets the name of the cached project image."""
  base_name = 'us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen'
  return f'{base_name}/{project.name}-ofg-cached-{sanitizer}'


def _get_project_cached_named_local(project: common_utils.Project,
                                    sanitizer='address'):
  return f'{project.name}-origin-{sanitizer}'


def build_cached_project(project: common_utils.Project,
                         cleanup: bool = True,
                         sanitizer: str = 'address'):
  """Build cached image for a project."""
  container_name = _get_project_cached_named_local(project, sanitizer)
  logger.info('Building cached image for project: %s', project)
  # Clean up the container if it exists.
  if cleanup:
    logger.info('Cleaning up existing container: %s', container_name)
    cmd = ['docker', 'container', 'rm', '-f', container_name]
    subprocess.run(cmd, check=False)

  project_language = 'c++'
  oss_fuzz_root = _get_oss_fuzz_root()
  # Build the cached image.
  cmd = [
      'docker', 'run', '--env=SANITIZER=' + sanitizer,
      '--env=CCACHE_DIR=/workspace/ccache',
      f'--env=FUZZING_LANGUAGE={project_language}',
      '--env=CAPTURE_REPLAY_SCRIPT=1', f'--name={container_name}',
      f'-v={oss_fuzz_root}/ccaches/{project.name}/ccache:/workspace/ccache',
      f'-v={oss_fuzz_root}/build/out/{project.name}/:/out/',
      '-v=' + os.path.join(oss_fuzz_root, 'infra', 'chronos') + ':/chronos/',
      f'gcr.io/oss-fuzz/{project.name}', '/bin/bash', '-c',
      '/chronos/container_cache_build.sh'
  ]

  logger.info('Command: %s', ' '.join(cmd))
  start = time.time()
  try:
    logger.info('Building cached container for project: %s', project.name)
    subprocess.check_call(cmd, cwd=oss_fuzz_root)
    end = time.time()
    logger.info('%s vanilla build Succeeded: Duration: %.2f seconds', project,
                end - start)
  except subprocess.CalledProcessError:
    end = time.time()
    logger.info('%s vanilla build Failed: Duration: %.2f seconds', project.name,
                end - start)
    return False

  # Save the container.
  cmd = [
      'docker', 'container', 'commit', '-c', "ENV REPLAY_ENABLED=1", '-c',
      "ENV CAPTURE_REPLAY_SCRIPT=1", container_name,
      _get_project_cached_named(project, sanitizer)
  ]
  logger.info('Saving image: [%s]', ' '.join(cmd))
  try:
    subprocess.check_call(cmd)

  except subprocess.CalledProcessError as e:
    logger.error('Failed to save cached image: %s', e)
    return False
  return True


def check_cached_replay(project: common_utils.Project,
                        sanitizer: str = 'address',
                        integrity_check: bool = False):
  """Checks if a cache build succeeds and times is.

  If integrity_check is True, will run with bad patches to validate
  the integrity of the cached replay build. The patches will perform three
  main tasks:
    1) A control test to ensure it's working as is.
    2) A control test to check that we rebuild when white noise is included.
    3) A set of bad patches that should cause the build to fail.
  """
  common_utils.build_image_impl(project)

  if not build_cached_project(project, sanitizer=sanitizer):
    logger.info('Failed to build cached image for project: %s', project.name)
    return

  start = time.time()
  cmd = [
      'docker',
      'run',
      '--rm',
      '--network',
      'none',
      '--env=SANITIZER=' + sanitizer,
      '--env=FUZZING_LANGUAGE=c++',
      '-v=' + os.path.join(_get_oss_fuzz_root(), 'build', 'out', project.name) +
      ':/out',
      '-v=' + os.path.join(_get_oss_fuzz_root(), 'infra', 'chronos') +
      ':/chronos',
      '--name=' + project.name + '-origin-' + sanitizer + '-replay-recached',
      _get_project_cached_named(project, sanitizer),
      '/bin/bash',
      '-c',
  ]

  if integrity_check:
    # Use different bad patches to test the cached replay build
    failed = []
    for bad_patch_name, bad_patch_map in integrity_validator_check_replay.BAD_PATCH_GENERATOR.items(
    ):
      # Generate bad patch command using different approaches
      expected_rc = bad_patch_map['rc']
      cmd_to_run = cmd[:]
      cmd_to_run.append(
          f'/chronos/container_patch_replay_test.sh {bad_patch_name}')

      # Run the cached replay script with bad patches
      result = subprocess.run(cmd_to_run, check=False)

      if result.returncode not in expected_rc:
        failed.append(bad_patch_name)
        logger.info(('%s check cached replay failed on bad patches %s. '
                     'Return code: %d. Expected return code: %s'), project.name,
                    bad_patch_name, result.returncode, str(expected_rc))

    if failed:
      logger.info(
          '%s check cached replay failed to detect these bad patches: %s',
          project.name, ' '.join(failed))
    else:
      logger.info('%s check cached replay success to detect all bad patches.',
                  project.name)
  else:
    # Normal run with no integrity check
    logger.info('Running cached replay with no integrity check for project: %s',
                project.name)
    base_cmd = 'export PATH=/ccache/bin:$PATH && rm -rf /out/* && compile'
    cmd.append(base_cmd)
    replay_success = False
    try:
      subprocess.run(cmd, check=True)
      replay_success = True
    except subprocess.CalledProcessError as e:
      logger.error('Failed to run cached replay: %s', e)
      replay_success = False
    logger.info('%s check cached replay: %s.', project.name,
                'succeeded' if replay_success else 'failed')

  end = time.time()
  logger.info('%s check cached replay completion time: %.2f seconds',
              project.name, (end - start))


def check_tests(project: common_utils.Project,
                sanitizer: str = 'address',
                run_full_cache_replay: bool = False,
                integrity_check: bool = False,
                stop_on_failure: bool = False,
                semantic_test: bool = False):
  """Run the `run_tests.sh` script for a specific project. Will
    build a cached container first.

  When `integrity_check` is True, a check that validates if the `run_test.sh` changes
  the source control of the project will be performed. That is, we want to ensure,
  e.g. `git diff ./` has the same output before and after `run_tests.sh`.
  Additionally, if `semantic_test` is
  True, a set of semantic patches will be applied to the source code of the project
  to validate if the `run_tests.sh` is able to detect them.
  """

  script_path = os.path.join('projects', project.name, 'run_tests.sh')

  if not os.path.exists(script_path):
    logger.info('Error: The script for project "%s" does not exist at %s',
                project.name, script_path)
    sys.exit(1)

  logger.info('Building image for project for use in check-tests: %s',
              project.name)
  # Build an OSS-Fuzz image of the project
  if run_full_cache_replay:
    check_cached_replay(project.name, sanitizer)
  else:
    common_utils.build_image_impl(project)

    # build a cached version of the project
    if not build_cached_project(project, sanitizer=sanitizer):
      logger.info('Failed to build cached image for project: %s', project.name)
      sys.exit(1)

  # Run the test script
  start = time.time()
  run_tests_cmd = 'chmod +x /src/run_tests.sh && /src/run_tests.sh'
  docker_cmd = [
      'docker',
      'run',
      '--rm',
      '--network',
      'none',
      '-e',
      'PROJECT_NAME=' + project.name,
      '-v=' + os.path.join(_get_oss_fuzz_root(), 'infra', 'chronos') +
      ':/chronos',
      _get_project_cached_named(project, sanitizer),
      '/bin/bash',
      '-c',
  ]

  if integrity_check or semantic_test:

    # Run normal build_test
    logger.info('Running normal run_tests.sh for project: %s', project.name)
    docker_cmd_vanilla = docker_cmd[:]
    docker_cmd_vanilla.append(run_tests_cmd)
    try:
      subprocess.check_call(docker_cmd_vanilla)
      logger.info('Successfully ran run_tests.sh for project: %s', project)
    except subprocess.CalledProcessError:
      logger.info(
          'run_tests.sh result failed: Failed to run vanilla run_tests.sh for project: %s',
          project.name)
      sys.exit(0)

    # First check diffing patch. The approach here is to capture a diff before
    # and after applying the patch, and see if there are any changes to e.g. git diff.
    logger.info('Checking diffing patch for project: %s', project.name)
    patch_command = (
        'python3 -m pip install -r /chronos/requirements.txt &&'
        'python3 /chronos/integrity_validator_run_tests.py diff-patch before')
    cmd_to_run = docker_cmd[:]

    # Capture the patch after.
    cmd_to_run.append('/chronos/container_patch_tests_test.sh')
    ret_code = 0
    try:
      subprocess.check_call(cmd_to_run)
    except subprocess.CalledProcessError as exc:
      ret_code = exc.returncode

    succeeded_patch = ret_code == 0
    logger.info('succeeded patch: %s', succeeded_patch)
    if ret_code == 0:
      patch_msg = 'run_tests.sh result succeeded: does not patch source control'
    elif ret_code == 1:
      patch_msg = 'run_tests.sh result failed: patches source control'
    else:
      patch_msg = 'run_tests.sh result uknown: unable to tell if run_tests.sh patches source control'
    logger.info('%s', patch_msg)
    patch_details = {
        'check-name': 'run_tests_patches_diff',
        'patch-message': patch_msg
    }
    succeeded = succeeded_patch
    if semantic_test:
      # Second, check semantic patching tests. This is a best effort and won't work on some
      # projects.
      integrity_checks = []
      # Patch the code with some logic error and see if build_test able to detect
      # them.
      for logic_patch in integrity_validator_run_tests.LOGIC_ERROR_PATCHES:
        logger.info('Checking logic patch: %s', logic_patch.name)
        patch_command = (
            'python3 -m pip install -r /chronos/requirements.txt &&'
            f'python3 /chronos/integrity_validator_run_tests.py semantic-patch {logic_patch.name} && '
            'compile')
        cmd_to_run = docker_cmd[:]

        # In the below, we will apply a set of changes in the source code, rebuild
        # the target and then run the run_tests.sh script.
        # The patches are meant to check the semantics of the code, but they are
        # not bulletproof, which means they may break the build in exceptional
        # circumstances. So, we first try to compile the code after having applied
        # the patches, but without running the tests, and if this step fails, then
        # we skip running the tests for this patch as well.
        # Patch and build first.
        cmd_to_run.append(f'set -euo pipefail && {patch_command}')
        try:
          subprocess.check_call(cmd_to_run)
        except subprocess.CalledProcessError:
          logger.info('%s skipping logic patch %s that failed to compile.',
                      project.name, logic_patch.name)
          integrity_checks.append({
              'patch': logic_patch.name,
              'result': 'compile_fail'
          })
          continue

        # Patch and build succeeded, now proceed to patch, build and run tests in
        # one go. This will indicate if the patch was detected by the tests or
        # not.
        cmd_to_run[
            -1] = f'set -euo pipefail && {patch_command} && {run_tests_cmd}'
        try:
          subprocess.check_call(cmd_to_run)
          exception_thrown = False
        except subprocess.CalledProcessError:
          exception_thrown = True

        if ((exception_thrown and not logic_patch.expected_result) or
            (not exception_thrown and logic_patch.expected_result)):
          # The patch was detected by the tests as it should have been.
          integrity_checks.append({
              'patch': logic_patch.name,
              'result': 'Success'
          })
        else:
          if stop_on_failure:
            logger.info(
                '%s integrity check failed on patch %s, stopping as requested.',
                project.name, logic_patch.name)
            return False
          integrity_checks.append({
              'patch': logic_patch.name,
              'result': 'Failed'
          })

      logger.info('%s integrity check results:', project.name)
      for check in integrity_checks:
        logger.info('%s integrity check patch %s result: %s', project.name,
                    check['patch'], check['result'])
      succeeded = any([chk['result'] == 'Success' for chk in integrity_checks])

      # Print patching results as well.
      logger.info('run_tests.sh patches version control: %s',
                  patch_details['patch-message'])
  else:
    # Run normal build_test
    docker_cmd.append(run_tests_cmd)
    try:
      subprocess.check_call(docker_cmd)
      succeeded = True
      succeeded_patch = True
    except subprocess.CalledProcessError:
      succeeded = False
      succeeded_patch = False

  end = time.time()

  result = succeeded and succeeded_patch
  logger.info('%s test completion %s: Duration of run_tests.sh: %.2f seconds',
              project.name, 'failed' if not result else 'succeeded',
              (end - start))

  return result


def extract_test_coverage(project):
  """Extract code coverage report from run_tests.sh script."""

  build_cached_project(project, sanitizer='coverage')

  os.makedirs(os.path.join('build', 'out', project.name), exist_ok=True)

  shared_folder = os.path.join(_get_oss_fuzz_root(), 'build', 'out',
                               project.name)
  cmd = [
      'docker', 'run', '--rm', '--network', 'none', '-v',
      f'{shared_folder}:/out', '-v=' +
      os.path.join(_get_oss_fuzz_root(), 'infra', 'chronos') + ':/chronos/',
      _get_project_cached_named(project, 'coverage'), '/bin/bash', '-c',
      '/chronos/container_coverage_collection.sh'
  ]
  try:
    subprocess.check_call(cmd)
  except subprocess.CalledProcessError as e:
    logger.error('Error occurred while running coverage collection: %s', e)
    return False

  # If the summary file is created, dump the total lines covered.
  if os.path.isfile(
      os.path.join('build', 'out', project, 'test-html-generation',
                   'summary.json')):
    summary_json = os.path.join('build', 'out', project, 'test-html-generation',
                                'summary.json')
    with open(summary_json, 'r', encoding='utf-8') as f:
      summary = json.load(f)
      total_lines_covered = summary['data'][0]['totals']['lines']
      logger.info('Total lines covered for %s: %s', project,
                  json.dumps(total_lines_covered))
  return True


def cmd_dispatcher_check_tests(args):
  """Dispatcher for check-tests command."""
  # This argument is not enabled by default in helper.py, so we set it here.
  args.semantic_test = getattr(args, 'semantic_test', False)
  check_tests(args.project, args.sanitizer, args.run_full_cache_replay,
              args.integrity_check, args.stop_on_failure, args.semantic_test)


def cmd_dispatcher_check_replay(args):
  """Dispatcher for check-replay command."""
  check_cached_replay(args.project,
                      args.sanitizer,
                      integrity_check=args.integrity_check)


def cmd_dispatcher_build_cached_image(args):
  """Dispatcher for build-cached-image command."""
  build_cached_project(args.project, sanitizer=args.sanitizer)


def cmd_dispatcher_extract_coverage(args):
  """Dispatcher for extract-test-coverage command."""
  extract_test_coverage(args.project)


def parse_args():
  """Parses command line arguments for the manager script."""
  parser = argparse.ArgumentParser(
      'manager.py',
      description='Chronos Manager: a tool for managing cached OSS-Fuzz builds.'
  )
  subparsers = parser.add_subparsers(dest='command')

  checks_test_parser = subparsers.add_parser(
      'check-tests', help='Checks run_test.sh for specific project.')
  checks_test_parser.add_argument(
      'project',
      type=str,
      help='The name of the project to check (e.g., "libpng").',
  )
  checks_test_parser.add_argument(
      '--stop-on-failure',
      action='store_true',
      help='If set, will stop integrity checks on first failure.')
  checks_test_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use (default: address).')
  checks_test_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')
  checks_test_parser.add_argument(
      '--run-full-cache-replay',
      action='store_true',
      help=
      'If set, will run the full cache replay instead of just checking the script.'
  )
  checks_test_parser.add_argument(
      '--integrity-check',
      action='store_true',
      help=
      'If set, will patch and test with logic errors to ensure build integrity.'
  )
  checks_test_parser.add_argument(
      '--semantic-test',
      help=
      'If set, will try and validate semantic correctness of run_tests.sh. This is beta for now.',
      action='store_true')

  check_replay_parser = subparsers.add_parser(
      'check-replay',
      help='Checks if the replay script works for a specific project.')

  check_replay_parser.add_argument('project',
                                   help='The name of the project to check.')
  check_replay_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')
  check_replay_parser.add_argument(
      '--integrity-check',
      action='store_true',
      help='If set, will test the integrity of the replay script.')

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

  args.project = common_utils.Project(args.project, False)

  dispatch_map = {
      'check-tests': cmd_dispatcher_check_tests,
      'check-replay': cmd_dispatcher_check_replay,
      'build-cached-image': cmd_dispatcher_build_cached_image,
      'extract-test-coverage': cmd_dispatcher_extract_coverage
  }

  dispatch_cmd = dispatch_map.get(args.command, None)
  if not dispatch_cmd:
    logger.error('Unknown command: %s', args.command)
    sys.exit(1)
  logger.info('Dispatching command: %s', args.command)
  dispatch_cmd(args)


if __name__ == '__main__':
  main()
