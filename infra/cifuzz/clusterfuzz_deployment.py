# Copyright 2021 Google LLC
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
"""Module for interacting with the "ClusterFuzz deployment."""
import logging
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


class BaseClusterFuzzDeployment:
  """Base class for ClusterFuzz deployments."""

  CORPUS_DIR_NAME = 'cifuzz-corpus'
  BUILD_DIR_NAME = 'cifuzz-latest-build'

  def __init__(self, config):
    self.config = config

  def download_latest_build(self, out_dir):
    """Downloads the latest build from ClusterFuzz.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def download_corpus(self, target_name, out_dir):
    """Downloads the corpus for |target_name| from ClusterFuzz to |out_dir|.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')


class ClusterFuzzLite(BaseClusterFuzzDeployment):
  """Class representing a deployment of ClusterFuzzLite."""

  def download_latest_build(self, out_dir):
    logging.info('download_latest_build not implemented for ClusterFuzzLite.')

  def download_corpus(self, target_name, out_dir):
    logging.info('download_corpus not implemented for ClusterFuzzLite.')


class OSSFuzz(BaseClusterFuzzDeployment):
  """The OSS-Fuzz ClusterFuzz deployment."""

  # Location of clusterfuzz builds on GCS.
  CLUSTERFUZZ_BUILDS = 'clusterfuzz-builds'

  # Format string for the latest version of a project's build.
  VERSION_STRING = '{project_name}-{sanitizer}-latest.version'

  # Zip file name containing the corpus.
  CORPUS_ZIP_NAME = 'public.zip'

  def get_latest_build_name(self):
    """Gets the name of the latest OSS-Fuzz build of a project.

    Returns:
      A string with the latest build version or None.
    """
    version_file = self.VERSION_STRING.format(
        project_name=self.config.project_name, sanitizer=self.config.sanitizer)
    version_url = utils.url_join(utils.GCS_BASE_URL, self.CLUSTERFUZZ_BUILDS,
                                 self.config.project_name, version_file)
    try:
      response = urllib.request.urlopen(version_url)
    except urllib.error.HTTPError:
      logging.error('Error getting latest build version for %s from: %s.',
                    self.config.project_name, version_url)
      return None
    return response.read().decode()

  def download_latest_build(self, out_dir):
    """Downloads the latest OSS-Fuzz build from GCS.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    build_dir = os.path.join(out_dir, self.BUILD_DIR_NAME)
    if os.path.exists(build_dir):
      return build_dir

    os.makedirs(build_dir, exist_ok=True)

    latest_build_name = self.get_latest_build_name()
    if not latest_build_name:
      return None

    oss_fuzz_build_url = utils.url_join(utils.GCS_BASE_URL,
                                        self.CLUSTERFUZZ_BUILDS,
                                        self.config.project_name,
                                        latest_build_name)
    if download_and_unpack_zip(oss_fuzz_build_url, build_dir):
      return build_dir

    return None

  def download_corpus(self, target_name, out_dir):
    """Downloads the latest OSS-Fuzz corpus for the target.

    Returns:
      The local path to to corpus or None if download failed.
    """
    corpus_dir = os.path.join(out_dir, self.CORPUS_DIR_NAME, target_name)
    os.makedirs(corpus_dir, exist_ok=True)
    # TODO(metzman): Clean up this code.
    project_qualified_fuzz_target_name = target_name
    qualified_name_prefix = self.config.project_name + '_'

    if not target_name.startswith(qualified_name_prefix):
      project_qualified_fuzz_target_name = qualified_name_prefix + target_name

    corpus_url = utils.url_join(
        utils.GCS_BASE_URL,
        '{0}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/'.format(
            self.config.project_name), project_qualified_fuzz_target_name,
        self.CORPUS_ZIP_NAME)

    if download_and_unpack_zip(corpus_url, corpus_dir):
      return corpus_dir

    return None


def download_url(url, filename, num_attempts=3):
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

  # TODO(metzman): Use retry.wrap here.
  for _ in range(num_attempts):
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

  logging.error('Failed to download %s, %d times.', url, num_attempts)

  return False


def download_and_unpack_zip(url, extract_directory):
  """Downloads and unpacks a zip file from an HTTP URL.

  Args:
    url: A url to the zip file to be downloaded and unpacked.
    out_dir: The path where the zip file should be extracted to.

  Returns:
    True on success.
  """
  if not os.path.exists(extract_directory):
    logging.error('Extract directory: %s does not exist.', extract_directory)
    return False

  # Gives the temporary zip file a unique identifier in the case that
  # that download_and_unpack_zip is done in parallel.
  with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_file:
    if not download_url(url, tmp_file.name):
      return False

    try:
      with zipfile.ZipFile(tmp_file.name, 'r') as zip_file:
        zip_file.extractall(extract_directory)
    except zipfile.BadZipFile:
      logging.error('Error unpacking zip from %s. Bad Zipfile.', url)
      return False

  return True


def get_clusterfuzz_deployment(config):
  """Returns object reprsenting deployment of ClusterFuzz used by |config|."""
  if (config.platform == config.Platform.INTERNAL_GENERIC_CI or
      config.platform == config.Platform.INTERNAL_GITHUB):
    logging.info('Using OSS-Fuzz as ClusterFuzz deployment.')
    return OSSFuzz(config)
  logging.info('Using ClusterFuzzLite as ClusterFuzz deployment.')
  return ClusterFuzzLite(config)
