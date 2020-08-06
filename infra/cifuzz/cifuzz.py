# Copyright 2020 Google LLC
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
"""Module used by CI tools in order to interact with fuzzers.
This module helps CI tools do the following:
  1. Build fuzzers.
  2. Run fuzzers.
Eventually it will be used to help CI tools determine which fuzzers to run.
"""

import json
import logging
import os
import shutil
import sys
import time
import urllib.error
import urllib.request

import fuzz_target

# pylint: disable=wrong-import-position
# pylint: disable=import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build_specified_commit
import helper
import repo_manager
import utils

# From clusterfuzz: src/python/crash_analysis/crash_analyzer.py
# Used to get the beginning of the stack trace.
STACKTRACE_TOOL_MARKERS = [
    'AddressSanitizer',
    'ASAN:',
    'CFI: Most likely a control flow integrity violation;',
    'ERROR: libFuzzer',
    'KASAN:',
    'LeakSanitizer',
    'MemorySanitizer',
    'ThreadSanitizer',
    'UndefinedBehaviorSanitizer',
    'UndefinedSanitizer',
]

# From clusterfuzz: src/python/crash_analysis/crash_analyzer.py
# Used to get the end of the stack trace.
STACKTRACE_END_MARKERS = [
    'ABORTING',
    'END MEMORY TOOL REPORT',
    'End of process memory map.',
    'END_KASAN_OUTPUT',
    'SUMMARY:',
    'Shadow byte and word',
    '[end of stack trace]',
    '\nExiting',
    'minidump has been written',
]

#  Default fuzz configuration.
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_ARCHITECTURE = 'x86_64'

# The path to get project's latest report json files.
LATEST_REPORT_INFO_PATH = 'oss-fuzz-coverage/latest_report_info/'

# TODO: Turn default logging to WARNING when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
def build_fuzzers(project_name,
                  project_repo_name,
                  workspace,
                  pr_ref=None,
                  commit_sha=None,
                  sanitizer='address'):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz project being built.
    project_repo_name: The name of the projects repo.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    pr_ref: The pull request reference to be built.
    commit_sha: The commit sha for the project to be built at.
    sanitizer: The sanitizer the fuzzers should be built with.

  Returns:
    True if build succeeded or False on failure.
  """
  # Validate inputs.
  assert pr_ref or commit_sha
  if not os.path.exists(workspace):
    logging.error('Invalid workspace: %s.', workspace)
    return False

  logging.info("Using %s sanitizer.", sanitizer)

  git_workspace = os.path.join(workspace, 'storage')
  os.makedirs(git_workspace, exist_ok=True)
  out_dir = os.path.join(workspace, 'out')
  os.makedirs(out_dir, exist_ok=True)

  # Detect repo information.
  inferred_url, oss_fuzz_repo_path = build_specified_commit.detect_main_repo(
      project_name, repo_name=project_repo_name)
  if not inferred_url or not oss_fuzz_repo_path:
    logging.error('Could not detect repo from project %s.', project_name)
    return False
  src_in_docker = os.path.dirname(oss_fuzz_repo_path)
  oss_fuzz_repo_name = os.path.basename(oss_fuzz_repo_path)

  # Checkout projects repo in the shared volume.
  build_repo_manager = repo_manager.RepoManager(inferred_url,
                                                git_workspace,
                                                repo_name=oss_fuzz_repo_name)
  try:
    if pr_ref:
      build_repo_manager.checkout_pr(pr_ref)
    else:
      build_repo_manager.checkout_commit(commit_sha)
  except (RuntimeError, ValueError):
    logging.error('Can not check out requested state %s.', pr_ref or commit_sha)
    logging.error('Using current repo state.')

  # Build Fuzzers using docker run.
  command = [
      '--cap-add',
      'SYS_PTRACE',
      '-e',
      'FUZZING_ENGINE=' + DEFAULT_ENGINE,
      '-e',
      'SANITIZER=' + sanitizer,
      '-e',
      'ARCHITECTURE=' + DEFAULT_ARCHITECTURE,
      '-e',
      'FUZZING_LANGUAGE=c++',  # FIXME: Add proper support.
  ]
  container = utils.get_container_name()
  if container:
    command += ['-e', 'OUT=' + out_dir, '--volumes-from', container]
    bash_command = 'rm -rf {0} && cp -r {1} {2} && compile'.format(
        os.path.join(src_in_docker, oss_fuzz_repo_name, '*'),
        os.path.join(git_workspace, oss_fuzz_repo_name), src_in_docker)
  else:
    command += [
        '-e', 'OUT=' + '/out', '-v',
        '%s:%s' % (os.path.join(git_workspace, oss_fuzz_repo_name),
                   os.path.join(src_in_docker, oss_fuzz_repo_name)), '-v',
        '%s:%s' % (out_dir, '/out')
    ]
    bash_command = 'compile'

  command.extend([
      'gcr.io/oss-fuzz/' + project_name,
      '/bin/bash',
      '-c',
  ])
  command.append(bash_command)
  if helper.docker_run(command):
    logging.error('Building fuzzers failed.')
    return False
  remove_unaffected_fuzzers(project_name, out_dir,
                            build_repo_manager.get_git_diff(),
                            oss_fuzz_repo_path)
  return True


def run_fuzzers(fuzz_seconds, workspace, project_name, sanitizer='address'):
  """Runs all fuzzers for a specific OSS-Fuzz project.

  Args:
    fuzz_seconds: The total time allotted for fuzzing.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    project_name: The name of the relevant OSS-Fuzz project.
    sanitizer: The sanitizer the fuzzers should be run with.

  Returns:
    (True if run was successful, True if bug was found).
  """
  # Validate inputs.
  if not os.path.exists(workspace):
    logging.error('Invalid workspace: %s.', workspace)
    return False, False

  logging.info("Using %s sanitizer.", sanitizer)

  out_dir = os.path.join(workspace, 'out')
  artifacts_dir = os.path.join(out_dir, 'artifacts')
  os.makedirs(artifacts_dir, exist_ok=True)
  if not fuzz_seconds or fuzz_seconds < 1:
    logging.error('Fuzz_seconds argument must be greater than 1, but was: %s.',
                  format(fuzz_seconds))
    return False, False

  # Get fuzzer information.
  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    logging.error('No fuzzers were found in out directory: %s.',
                  format(out_dir))
    return False, False

  # Run fuzzers for alotted time.
  total_num_fuzzers = len(fuzzer_paths)
  fuzzers_left_to_run = total_num_fuzzers
  min_seconds_per_fuzzer = fuzz_seconds // total_num_fuzzers
  for fuzzer_path in fuzzer_paths:
    run_seconds = max(fuzz_seconds // fuzzers_left_to_run,
                      min_seconds_per_fuzzer)

    target = fuzz_target.FuzzTarget(fuzzer_path,
                                    run_seconds,
                                    out_dir,
                                    project_name,
                                    sanitizer=sanitizer)
    start_time = time.time()
    test_case, stack_trace = target.fuzz()
    fuzz_seconds -= (time.time() - start_time)
    if not test_case or not stack_trace:
      logging.info('Fuzzer %s, finished running.', target.target_name)
    else:
      logging.info('Fuzzer %s, detected error: %s.', target.target_name,
                   stack_trace)
      shutil.move(test_case, os.path.join(artifacts_dir, 'test_case'))
      parse_fuzzer_output(stack_trace, artifacts_dir)
      return True, True
    fuzzers_left_to_run -= 1

  return True, False


def check_fuzzer_build(out_dir, sanitizer='address'):
  """Checks the integrity of the built fuzzers.

  Args:
    out_dir: The directory containing the fuzzer binaries.
    sanitizer: The sanitizer the fuzzers are built with.

  Returns:
    True if fuzzers are correct.
  """
  if not os.path.exists(out_dir):
    logging.error('Invalid out directory: %s.', out_dir)
    return False
  if not os.listdir(out_dir):
    logging.error('No fuzzers found in out directory: %s.', out_dir)
    return False

  command = [
      '--cap-add',
      'SYS_PTRACE',
      '-e',
      'FUZZING_ENGINE=' + DEFAULT_ENGINE,
      '-e',
      'SANITIZER=' + sanitizer,
      '-e',
      'ARCHITECTURE=' + DEFAULT_ARCHITECTURE,
  ]

  # Set ALLOWED_BROKEN_TARGETS_PERCENTAGE in docker if specified by user.
  allowed_broken_targets_percentage = os.getenv(
      'ALLOWED_BROKEN_TARGETS_PERCENTAGE')
  if allowed_broken_targets_percentage is not None:
    command += [
        '-e',
        ('ALLOWED_BROKEN_TARGETS_PERCENTAGE=' +
         allowed_broken_targets_percentage)
    ]

  container = utils.get_container_name()
  if container:
    command += ['-e', 'OUT=' + out_dir, '--volumes-from', container]
  else:
    command += ['-v', '%s:/out' % out_dir]
  command.extend(['-t', 'gcr.io/oss-fuzz-base/base-runner', 'test_all'])
  exit_code = helper.docker_run(command)
  if exit_code:
    logging.error('Check fuzzer build failed.')
    return False
  return True


def get_latest_cov_report_info(project_name):
  """Gets latest coverage report info for a specific OSS-Fuzz project from GCS.

  Args:
    project_name: The name of the relevant OSS-Fuzz project.

  Returns:
    The projects coverage report info in json dict or None on failure.
  """
  latest_report_info_url = fuzz_target.url_join(fuzz_target.GCS_BASE_URL,
                                                LATEST_REPORT_INFO_PATH,
                                                project_name + '.json')
  latest_cov_info_json = get_json_from_url(latest_report_info_url)
  if not latest_cov_info_json:
    logging.error('Could not get the coverage report json from url: %s.',
                  latest_report_info_url)
    return None
  return latest_cov_info_json


def get_target_coverage_report(latest_cov_info, target_name):
  """Get the coverage report for a specific fuzz target.

  Args:
    latest_cov_info: A dict containing a project's latest cov report info.
    target_name: The name of the fuzz target whose coverage is requested.

  Returns:
    The targets coverage json dict or None on failure.
  """
  if 'fuzzer_stats_dir' not in latest_cov_info:
    logging.error('The latest coverage report information did not contain'
                  '\'fuzzer_stats_dir\' key.')
    return None
  fuzzer_report_url_segment = latest_cov_info['fuzzer_stats_dir']

  # Converting gs:// to http://
  fuzzer_report_url_segment = fuzzer_report_url_segment.replace('gs://', '')
  target_url = fuzz_target.url_join(fuzz_target.GCS_BASE_URL,
                                    fuzzer_report_url_segment,
                                    target_name + '.json')
  return get_json_from_url(target_url)


def get_files_covered_by_target(latest_cov_info, target_name,
                                oss_fuzz_repo_path):
  """Gets a list of files covered by the specific fuzz target.

  Args:
    latest_cov_info: A dict containing a project's latest cov report info.
    target_name: The name of the fuzz target whose coverage is requested.
    oss_fuzz_repo_path: The location of the repo in the docker image.

  Returns:
    A list of files that the fuzzer covers or None.
  """
  if not oss_fuzz_repo_path:
    logging.error('Project souce location in docker is not found.'
                  'Can\'t get coverage information from OSS-Fuzz.')
    return None
  target_cov = get_target_coverage_report(latest_cov_info, target_name)
  if not target_cov:
    return None
  coverage_per_file = target_cov['data'][0]['files']
  if not coverage_per_file:
    logging.info('No files found in coverage report.')
    return None

  # Make sure cases like /src/curl and /src/curl/ are both handled.
  norm_oss_fuzz_repo_path = os.path.normpath(oss_fuzz_repo_path)
  if not norm_oss_fuzz_repo_path.endswith('/'):
    norm_oss_fuzz_repo_path += '/'

  affected_file_list = []
  for file in coverage_per_file:
    norm_file_path = os.path.normpath(file['filename'])
    if not norm_file_path.startswith(norm_oss_fuzz_repo_path):
      continue
    if not file['summary']['regions']['count']:
      # Don't consider a file affected if code in it is never executed.
      continue

    relative_path = file['filename'].replace(norm_oss_fuzz_repo_path, '')
    affected_file_list.append(relative_path)
  if not affected_file_list:
    return None
  return affected_file_list


def remove_unaffected_fuzzers(project_name, out_dir, files_changed,
                              oss_fuzz_repo_path):
  """Removes all non affected fuzzers in the out directory.

  Args:
    project_name: The name of the relevant OSS-Fuzz project.
    out_dir: The location of the fuzzer binaries.
    files_changed: A list of files changed compared to HEAD.
    oss_fuzz_repo_path: The location of the OSS-Fuzz repo in the docker image.
  """
  if not files_changed:
    logging.info('No files changed compared to HEAD.')
    return
  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    logging.error('No fuzzers found in out dir.')
    return

  latest_cov_report_info = get_latest_cov_report_info(project_name)
  if not latest_cov_report_info:
    logging.error('Could not download latest coverage report.')
    return
  affected_fuzzers = []
  logging.info('Files changed in PR:\n%s', '\n'.join(files_changed))
  for fuzzer in fuzzer_paths:
    fuzzer_name = os.path.basename(fuzzer)
    covered_files = get_files_covered_by_target(latest_cov_report_info,
                                                fuzzer_name, oss_fuzz_repo_path)
    if not covered_files:
      # Assume a fuzzer is affected if we can't get its coverage from OSS-Fuzz.
      affected_fuzzers.append(fuzzer_name)
      continue
    logging.info('Fuzzer %s has affected files:\n%s', fuzzer_name,
                 '\n'.join(covered_files))
    for file in files_changed:
      if file in covered_files:
        affected_fuzzers.append(fuzzer_name)

  if not affected_fuzzers:
    logging.info('No affected fuzzers detected, keeping all as fallback.')
    return
  logging.info('Using affected fuzzers.\n %s fuzzers affected by pull request',
               ' '.join(affected_fuzzers))

  all_fuzzer_names = map(os.path.basename, fuzzer_paths)

  # Remove all the fuzzers that are not affected.
  for fuzzer in all_fuzzer_names:
    if fuzzer not in affected_fuzzers:
      try:
        os.remove(os.path.join(out_dir, fuzzer))
      except OSError as error:
        logging.error('%s occured while removing file %s', error, fuzzer)


def get_json_from_url(url):
  """Gets a json object from a specified http url.

  Args:
    url: The url of the json to be downloaded.

  Returns:
    Json dict or None on failure.
  """
  try:
    response = urllib.request.urlopen(url)
  except urllib.error.HTTPError:
    logging.error('HTTP error with url %s.', url)
    return None
  try:
    # read().decode() fixes compatability issue with urllib response object.
    result_json = json.loads(response.read().decode())
  except (ValueError, TypeError, json.JSONDecodeError) as excp:
    logging.error('Loading json from url %s failed with: %s.', url, str(excp))
    return None
  return result_json


def parse_fuzzer_output(fuzzer_output, out_dir):
  """Parses the fuzzer output from a fuzz target binary.

  Args:
    fuzzer_output: A fuzz target binary output string to be parsed.
    out_dir: The location to store the parsed output files.
  """
  # Get index of key file points.
  for marker in STACKTRACE_TOOL_MARKERS:
    marker_index = fuzzer_output.find(marker)
    if marker_index:
      begin_summary = marker_index
      break

  end_summary = -1
  for marker in STACKTRACE_END_MARKERS:
    marker_index = fuzzer_output.find(marker)
    if marker_index:
      end_summary = marker_index + len(marker)
      break

  if begin_summary is None or end_summary is None:
    return

  summary_str = fuzzer_output[begin_summary:end_summary]
  if not summary_str:
    return

  # Write sections of fuzzer output to specific files.
  summary_file_path = os.path.join(out_dir, 'bug_summary.txt')
  with open(summary_file_path, 'a') as summary_handle:
    summary_handle.write(summary_str)
