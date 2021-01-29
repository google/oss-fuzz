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
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

# TODO: Turn default logging to WARNING when CIFuzz is stable.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

LIBFUZZER_OPTIONS = '-seed=1337 -len_control=0'

# Location of cluster fuzz builds on GCS.
CLUSTERFUZZ_BUILDS = 'clusterfuzz-builds'

# The get request for the latest version of a project's build.
VERSION_STRING = '{project_name}-{sanitizer}-latest.version'

# The name to store the latest OSS-Fuzz build at.
BUILD_ARCHIVE_NAME = 'oss_fuzz_latest.zip'

# Zip file name containing the corpus.
CORPUS_ZIP_NAME = 'public.zip'

# The number of reproduce attempts for a crash.
REPRODUCE_ATTEMPTS = 10

# Seconds on top of duration until a timeout error is raised.
BUFFER_TIME = 10

# Log message for is_crash_reportable if it can't check if crash reproduces on
# an OSS-Fuzz build.
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

  # pylint: disable=too-many-arguments
  def __init__(self,
               target_path,
               duration,
               out_dir,
               project_name=None,
               sanitizer='address'):
    """Represents a single fuzz target.

    Note: project_name should be none when the fuzzer being run is not
    associated with a specific OSS-Fuzz project.

    Args:
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
      out_dir: The location of where the output from crashes should be stored.
      project_name: The name of the relevant OSS-Fuzz project.
    """
    # TODO(metzman): Get rid of sanitizer defaulting to address. config_utils
    # implements this functionality. Also look into why project_name defaults to
    # None. Maybe accept config and get those values from there.
    self.target_path = target_path
    self.target_name = os.path.basename(self.target_path)
    self.duration = int(duration)
    self.out_dir = out_dir
    self.project_name = project_name
    self.sanitizer = sanitizer

  def fuzz(self):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      (testcase, stacktrace, time in seconds) on crash or
      (None, None, time in seconds) on timeout or error.
    """
    # TODO(metzman): Change return value to a FuzzResult object.
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
        '-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=' + self.sanitizer,
        '-e', 'CIFUZZ=True', '-e', 'RUN_FUZZER_MODE=interactive',
        'gcr.io/oss-fuzz-base/base-runner', 'bash', '-c'
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
      _, stderr = process.communicate(timeout=self.duration + BUFFER_TIME)
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
    testcase = self.get_testcase(stderr)
    if not testcase:
      logging.error(b'No testcase found in stacktrace: %s.', stderr)
      return None, None
    if self.is_crash_reportable(testcase):
      return testcase, stderr
    return None, None

  def is_reproducible(self, testcase, target_path):
    """Checks if the testcase reproduces.

      Args:
        testcase: The path to the testcase to be tested.
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
          'TESTCASE=' + testcase
      ]
    else:
      command += [
          '-v',
          '%s:/out' % target_dirname, '-v',
          '%s:/testcase' % testcase
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

  def is_crash_reportable(self, testcase):
    """Returns True if a crash is reportable. This means the crash is
    reproducible but not reproducible on a build from OSS-Fuzz (meaning the
    crash was introduced by this PR).

    NOTE: If no project is specified the crash is assumed introduced
    by the pull request if it is reproducible.

    Args:
      testcase: The path to the testcase that triggered the crash.

    Returns:
      True if the crash was introduced by the current pull request.

    Raises:
      ReproduceError if we can't attempt to reproduce the crash on the PR build.
    """
    if not os.path.exists(testcase):
      raise ReproduceError('Testcase %s not found.' % testcase)

    try:
      reproducible_on_pr_build = self.is_reproducible(testcase,
                                                      self.target_path)
    except ReproduceError as error:
      logging.error('Could not run target when checking for reproducibility.'
                    'Please file an issue:'
                    'https://github.com/google/oss-fuzz/issues/new.')
      raise error

    if not self.project_name:
      return reproducible_on_pr_build

    if not reproducible_on_pr_build:
      logging.info('Failed to reproduce the crash using the obtained testcase.')
      return False

    oss_fuzz_build_dir = self.download_oss_fuzz_build()
    if not oss_fuzz_build_dir:
      # Crash is reproducible on PR build and we can't test on OSS-Fuzz build.
      logging.info(COULD_NOT_TEST_ON_OSS_FUZZ_MESSAGE)
      return True

    oss_fuzz_target_path = os.path.join(oss_fuzz_build_dir, self.target_name)
    try:
      reproducible_on_oss_fuzz_build = self.is_reproducible(
          testcase, oss_fuzz_target_path)
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

  def get_testcase(self, error_bytes):
    """Gets the file from a fuzzer run stacktrace.

    Args:
      error_bytes: The bytes containing the output from the fuzzer.

    Returns:
      The path to the testcase or None if not found.
    """
    match = re.search(rb'\bTest unit written to \.\/([^\s]+)', error_bytes)
    if match:
      return os.path.join(self.out_dir, match.group(1).decode('utf-8'))
    return None

  def get_latest_build_version(self):
    """Gets the latest OSS-Fuzz build version for a projects' fuzzers.

    Returns:
      A string with the latest build version or None.
    """
    if not self.project_name:
      return None

    version = VERSION_STRING.format(project_name=self.project_name,
                                    sanitizer=self.sanitizer)
    version_url = utils.url_join(utils.GCS_BASE_URL, CLUSTERFUZZ_BUILDS,
                                 self.project_name, version)
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
    latest_build_str = self.get_latest_build_version()
    if not latest_build_str:
      return None

    oss_fuzz_build_url = utils.url_join(utils.GCS_BASE_URL, CLUSTERFUZZ_BUILDS,
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
    corpus_url = utils.url_join(
        utils.GCS_BASE_URL,
        '{0}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/'.format(
            self.project_name), project_qualified_fuzz_target_name,
        CORPUS_ZIP_NAME)
    return download_and_unpack_zip(corpus_url, corpus_dir)


def download_url(url, filename, num_retries=3):
  """Downloads the file located at |url|, using HTTP to |filename|.

  Args:
    url: A url to a file to download.
    filename: The path the file should be downloaded to.
    num_retries: The number of times to retry the download on
       ConnectionResetError.

  Returns:
    True on success.
  """
  sleep_time = 1

  for _ in range(num_retries):
    try:
      urllib.request.urlretrieve(url, filename)
      return True
    except urllib.error.HTTPError:
      # In these cases, retrying probably wont work since the error probably
      # means there is nothing at the URL to download.
      logging.error('Unable to download from: %s.', url)
      return False
    except ConnectionResetError:
      # These errors are more likely to be transient. Retry.
      pass
    time.sleep(sleep_time)

  logging.error('Failed to download %s, %d times.', url, num_retries)

  return False


def download_and_unpack_zip(url, out_dir):
  """Downloads and unpacks a zip file from an HTTP URL.

  Args:
    url: A url to the zip file to be downloaded and unpacked.
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
    result = download_url(url, tmp_file.name)
    if not result:
      return None

    try:
      with zipfile.ZipFile(tmp_file.name, 'r') as zip_file:
        zip_file.extractall(out_dir)
    except zipfile.BadZipFile:
      logging.error('Error unpacking zip from %s. Bad Zipfile.', url)
      return None
  return out_dir
