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
"""A module to handle running a fuzz target for a specified amount of time."""
import logging
import os
import posixpath
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

# pylint: disable=wrong-import-position
# pylint: disable=import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

# TODO: Turn default logging to WARNING when CIFuzz is stable.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

LIBFUZZER_OPTIONS = '-seed=1337 -len_control=0'

# Location of google cloud storage for latest OSS-Fuzz builds.
GCS_BASE_URL = 'https://storage.googleapis.com/'

# Location of cluster fuzz builds on GCS.
CLUSTERFUZZ_BUILDS = 'clusterfuzz-builds'

# The get request for the latest version of a project's build.
VERSION_STRING = '{project_name}-{sanitizer}-latest.version'

# The name to store the latest OSS-Fuzz build at.
BUILD_ARCHIVE_NAME = 'oss_fuzz_latest.zip'

# Zip file name containing the corpus.
CORPUS_ZIP_NAME = 'public.zip'

# The sanitizer build to download.
SANITIZER = 'address'

# The number of reproduce attempts for a crash.
REPRODUCE_ATTEMPTS = 10

# Seconds on top of duration until a timeout error is raised.
BUFFER_TIME = 10

# Log message for is_crash_reportable if it can't check if crash repros
# on OSS-Fuzz build.
COULD_NOT_TEST_ON_OSS_FUZZ_MESSAGE = (
    'Crash is reproducible. Could not run OSS-Fuzz build of '
    'target to determine if this pull request introduced crash. '
    'Assuming this pull request introduced crash.')


class ReproduceError(Exception):
  """Error for when we can't attempt to reproduce a crash."""


class FuzzTarget:
  """A class to manage a single fuzz target.

  Attributes:
    target_name: The name of the fuzz target.
    duration: The length of time in seconds that the target should run.
    target_path: The location of the fuzz target binary.
    out_dir: The location of where output artifacts are stored.
    project_name: The name of the relevant OSS-Fuzz project.
  """

  def __init__(self, target_path, duration, out_dir, project_name=None):
    """Represents a single fuzz target.

    Note: project_name should be none when the fuzzer being run is not
    associated with a specific OSS-Fuzz project.

    Args:
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
      out_dir: The location of where the output from crashes should be stored.
      project_name: The name of the relevant OSS-Fuzz project.
    """
    self.target_name = os.path.basename(target_path)
    self.duration = int(duration)
    self.target_path = target_path
    self.out_dir = out_dir
    self.project_name = project_name

  def fuzz(self):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      (test_case, stack trace, time in seconds) on crash or
      (None, None, time in seconds) on timeout or error.
    """
    logging.info('Fuzzer %s, started.', self.target_name)
    docker_container = utils.get_container_name()
    command = ['docker', 'run', '--rm', '--privileged']
    if docker_container:
      command += [
          '--volumes-from', docker_container, '-e', 'OUT=' + self.out_dir
      ]
    else:
      command += ['-v', '%s:%s' % (self.out_dir, '/out')]

    command += [
        '-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=address', '-e',
        'RUN_FUZZER_MODE=interactive', 'gcr.io/oss-fuzz-base/base-runner',
        'bash', '-c'
    ]

    run_fuzzer_command = 'run_fuzzer {fuzz_target} {options}'.format(
        fuzz_target=self.target_name,
        options=LIBFUZZER_OPTIONS + ' -max_total_time=' + str(self.duration))

    # If corpus can be downloaded use it for fuzzing.
    latest_corpus_path = self.download_latest_corpus()
    if latest_corpus_path:
      run_fuzzer_command = run_fuzzer_command + ' ' + latest_corpus_path
    command.append(run_fuzzer_command)

    logging.info('Running command: %s', ' '.join(command))
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    try:
      _, err = process.communicate(timeout=self.duration + BUFFER_TIME)
    except subprocess.TimeoutExpired:
      logging.error('Fuzzer %s timed out, ending fuzzing.', self.target_name)
      return None, None

    # Libfuzzer timeout was reached.
    if not process.returncode:
      logging.info('Fuzzer %s finished with no crashes discovered.',
                   self.target_name)
      return None, None

    # Crash was discovered.
    logging.info('Fuzzer %s, ended before timeout.', self.target_name)
    err_str = err.decode('ascii')
    test_case = self.get_test_case(err_str)
    if not test_case:
      logging.error('No test case found in stack trace: %s.', err_str)
      return None, None
    if self.is_crash_reportable(test_case):
      return test_case, err_str
    return None, None

  def is_reproducible(self, test_case, target_path):
    """Checks if the test case reproduces.

      Args:
        test_case: The path to the test case to be tested.
        target_path: The path to the fuzz target to be tested

      Returns:
        True if crash is reproducible and we were able to run the
        binary.

      Raises:
        ReproduceError if we can't attempt to reproduce the crash.
    """

    if not os.path.exists(target_path):
      raise ReproduceError('Target %s not found.' % target_path)

    os.chmod(target_path, stat.S_IRWXO)

    target_dirname = os.path.dirname(target_path)
    command = ['docker', 'run', '--rm', '--privileged']
    container = utils.get_container_name()
    if container:
      command += [
          '--volumes-from', container, '-e', 'OUT=' + target_dirname, '-e',
          'TESTCASE=' + test_case
      ]
    else:
      command += [
          '-v',
          '%s:/out' % target_dirname, '-v',
          '%s:/testcase' % test_case
      ]

    command += [
        '-t', 'gcr.io/oss-fuzz-base/base-runner', 'reproduce', self.target_name,
        '-runs=100'
    ]

    logging.info('Running reproduce command: %s.', ' '.join(command))
    for _ in range(REPRODUCE_ATTEMPTS):
      _, _, returncode = utils.execute(command)
      if returncode != 0:
        logging.info('Reproduce command returned: %s. Reproducible on %s.',
                     returncode, target_path)

        return True

    logging.info('Reproduce command returned 0. Not reproducible on %s.',
                 target_path)
    return False

  def is_crash_reportable(self, test_case):
    """Returns True if a crash is reportable. This means the crash is
    reproducible but not reproducible on a build from OSS-Fuzz (meaning the
    crash was introduced by this PR).

    NOTE: If no project is specified the crash is assumed introduced
    by the pull request if it is reproducible.

    Args:
      test_case: The path to the test_case that triggered the crash.

    Returns:
      True if the crash was introduced by the current pull request.

    Raises:
      ReproduceError if we can't attempt to reproduce the crash on the PR build.
    """
    if not os.path.exists(test_case):
      raise ReproduceError('Test case %s not found.' % test_case)

    try:
      reproducible_on_pr_build = self.is_reproducible(test_case,
                                                      self.target_path)
    except ReproduceError as error:
      logging.error('Could not run target when checking for reproducibility.'
                    'Please file an issue:'
                    'https://github.com/google/oss-fuzz/issues/new.')
      raise error

    if not self.project_name:
      return reproducible_on_pr_build

    if not reproducible_on_pr_build:
      logging.info(
          'Failed to reproduce the crash using the obtained test case.')
      return False

    oss_fuzz_build_dir = self.download_oss_fuzz_build()
    if not oss_fuzz_build_dir:
      # Crash is reproducible on PR build and we can't test on OSS-Fuzz build.
      logging.info(COULD_NOT_TEST_ON_OSS_FUZZ_MESSAGE)
      return True

    oss_fuzz_target_path = os.path.join(oss_fuzz_build_dir, self.target_name)
    try:
      reproducible_on_oss_fuzz_build = self.is_reproducible(
          test_case, oss_fuzz_target_path)
    except ReproduceError:
      # This happens if the project has OSS-Fuzz builds, but the fuzz target
      # is not in it (e.g. because the fuzz target is new).
      logging.info(COULD_NOT_TEST_ON_OSS_FUZZ_MESSAGE)
      return True

    if not reproducible_on_oss_fuzz_build:
      logging.info('The crash is reproducible. The crash doesn\'t reproduce '
                   'on old builds. This pull request probably introduced the '
                   'crash.')
      return True

    logging.info('The crash is reproducible without the current pull request.')
    return False

  def get_test_case(self, error_string):
    """Gets the file from a fuzzer run stack trace.

    Args:
      error_string: The stack trace string containing the error.

    Returns:
      The error test case or None if not found.
    """
    match = re.search(r'\bTest unit written to \.\/([^\s]+)', error_string)
    if match:
      return os.path.join(self.out_dir, match.group(1))
    return None

  def get_lastest_build_version(self):
    """Gets the latest OSS-Fuzz build version for a projects' fuzzers.

    Returns:
      A string with the latest build version or None.
    """
    if not self.project_name:
      return None

    version = VERSION_STRING.format(project_name=self.project_name,
                                    sanitizer=SANITIZER)
    version_url = url_join(GCS_BASE_URL, CLUSTERFUZZ_BUILDS, self.project_name,
                           version)
    try:
      response = urllib.request.urlopen(version_url)
    except urllib.error.HTTPError:
      logging.error('Error getting latest build version for %s with url %s.',
                    self.project_name, version_url)
      return None
    return response.read().decode()

  def download_oss_fuzz_build(self):
    """Downloads the latest OSS-Fuzz build from GCS.

    Returns:
      A path to where the OSS-Fuzz build is located, or None.
    """
    if not os.path.exists(self.out_dir):
      logging.error('Out directory %s does not exist.', self.out_dir)
      return None
    if not self.project_name:
      return None

    build_dir = os.path.join(self.out_dir, 'oss_fuzz_latest', self.project_name)
    if os.path.exists(os.path.join(build_dir, self.target_name)):
      return build_dir
    os.makedirs(build_dir, exist_ok=True)
    latest_build_str = self.get_lastest_build_version()
    if not latest_build_str:
      return None

    oss_fuzz_build_url = url_join(GCS_BASE_URL, CLUSTERFUZZ_BUILDS,
                                  self.project_name, latest_build_str)
    return download_and_unpack_zip(oss_fuzz_build_url, build_dir)

  def download_latest_corpus(self):
    """Downloads the latest OSS-Fuzz corpus for the target from google cloud.

    Returns:
      The local path to to corpus or None if download failed.
    """
    if not self.project_name:
      return None
    if not os.path.exists(self.out_dir):
      logging.error('Out directory %s does not exist.', self.out_dir)
      return None

    corpus_dir = os.path.join(self.out_dir, 'backup_corpus', self.target_name)
    os.makedirs(corpus_dir, exist_ok=True)
    project_qualified_fuzz_target_name = self.target_name
    qualified_name_prefix = '%s_' % self.project_name
    if not self.target_name.startswith(qualified_name_prefix):
      project_qualified_fuzz_target_name = qualified_name_prefix + \
      self.target_name
    corpus_url = url_join(
        GCS_BASE_URL,
        '{0}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/'.format(
            self.project_name), project_qualified_fuzz_target_name,
        CORPUS_ZIP_NAME)
    return download_and_unpack_zip(corpus_url, corpus_dir)


def download_and_unpack_zip(http_url, out_dir):
  """Downloads and unpacks a zip file from an http url.

  Args:
    http_url: A url to the zip file to be downloaded and unpacked.
    out_dir: The path where the zip file should be extracted to.

  Returns:
    A path to the extracted file or None on failure.
  """
  if not os.path.exists(out_dir):
    logging.error('Out directory %s does not exist.', out_dir)
    return None

  # Gives the temporary zip file a unique identifier in the case that
  # that download_and_unpack_zip is done in parallel.
  with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_file:
    try:
      urllib.request.urlretrieve(http_url, tmp_file.name)
    except urllib.error.HTTPError:
      logging.error('Unable to download build from: %s.', http_url)
      return None

    try:
      with zipfile.ZipFile(tmp_file.name, 'r') as zip_file:
        zip_file.extractall(out_dir)
    except zipfile.BadZipFile:
      logging.error('Error unpacking zip from %s. Bad Zipfile.', http_url)
      return None
  return out_dir


def url_join(*url_parts):
  """Joins URLs together using the posix join method.

  Args:
    url_parts: Sections of a URL to be joined.

  Returns:
    Joined URL.
  """
  return posixpath.join(*url_parts)
