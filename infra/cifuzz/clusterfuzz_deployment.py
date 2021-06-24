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
"""Module for interacting with the ClusterFuzz deployment."""
import logging
import os
import sys
import urllib.error
import urllib.request

import http_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


class BaseClusterFuzzDeployment:
  """Base class for ClusterFuzz deployments."""

  def __init__(self, config, workspace):
    self.config = config
    self.workspace = workspace

  def download_latest_build(self):
    """Downloads the latest build from ClusterFuzz.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_latest_build(self):
    """Uploads the latest build to the filestore.
    Returns:
      True on success.
    """
    raise NotImplementedError('Child class must implement method.')

  def download_corpus(self, target_name):
    """Downloads the corpus for |target_name| from ClusterFuzz to |parent_dir|.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_crashes(self):
    """Uploads crashes in |crashes_dir| to filestore."""
    raise NotImplementedError('Child class must implement method.')

  def get_target_corpus_dir(self, target_name):
    """Returns the path to the corpus dir for |target_name|."""
    return os.path.join(self.workspace.corpora, target_name)

  def upload_corpus(self, target_name):  # pylint: disable=no-self-use,unused-argument
    """Uploads the corpus for |target_name| to filestore."""
    raise NotImplementedError('Child class must implement method.')


class ClusterFuzzLite(BaseClusterFuzzDeployment):
  """Class representing a deployment of ClusterFuzzLite."""

  def download_latest_build(self):
    logging.info('download_latest_build not implemented for ClusterFuzzLite.')

  def download_corpus(self, target_name):
    logging.info('download_corpus not implemented for ClusterFuzzLite.')

  def upload_corpus(self, target_name):  # pylint: disable=no-self-use,unused-argument
    logging.info('upload_corpus not implemented for ClusterFuzzLite.')

  def upload_latest_build(self):
    """Uploads the latest build to the filestore.
    Returns:
      True on success.
    """
    logging.info('upload_latest_build not implemented for ClusterFuzzLite.')

  def upload_crashes(self):
    logging.info('upload_crashes not implemented for ClusterFuzzLite.')


class OSSFuzz(BaseClusterFuzzDeployment):
  """The OSS-Fuzz ClusterFuzz deployment."""

  # Location of clusterfuzz builds on GCS.
  CLUSTERFUZZ_BUILDS = 'clusterfuzz-builds'

  # Zip file name containing the corpus.
  CORPUS_ZIP_NAME = 'public.zip'

  def get_latest_build_name(self):
    """Gets the name of the latest OSS-Fuzz build of a project.

    Returns:
      A string with the latest build version or None.
    """
    version_file = (f'{self.config.project_name}-{self.config.sanitizer}'
                    '-latest.version')
    version_url = utils.url_join(utils.GCS_BASE_URL, self.CLUSTERFUZZ_BUILDS,
                                 self.config.project_name, version_file)
    try:
      response = urllib.request.urlopen(version_url)
    except urllib.error.HTTPError:
      logging.error('Error getting latest build version for %s from: %s.',
                    self.config.project_name, version_url)
      return None
    return response.read().decode()

  def download_latest_build(self):
    """Downloads the latest OSS-Fuzz build from GCS.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    if os.path.exists(self.workspace.clusterfuzz_build):
      # This function can be called multiple times, don't download the build
      # again.
      return self.workspace.clusterfuzz_build

    os.makedirs(self.workspace.clusterfuzz_build, exist_ok=True)

    latest_build_name = self.get_latest_build_name()
    if not latest_build_name:
      return None

    oss_fuzz_build_url = utils.url_join(utils.GCS_BASE_URL,
                                        self.CLUSTERFUZZ_BUILDS,
                                        self.config.project_name,
                                        latest_build_name)
    if http_utils.download_and_unpack_zip(oss_fuzz_build_url,
                                          self.workspace.clusterfuzz_build):
      return self.workspace.clusterfuzz_build

    return None

  def upload_latest_build(self):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_latest_build."""
    logging.info('Not uploading latest build because on OSS-Fuzz.')

  def upload_corpus(self, target_name):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_corpus."""
    logging.info('Not uploading corpus because on OSS-Fuzz.')

  def upload_crashes(self):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_crashes."""
    logging.info('Not uploading crashes on OSS-Fuzz.')

  def download_corpus(self, target_name):
    """Downloads the latest OSS-Fuzz corpus for the target.

    Returns:
      The local path to to corpus or None if download failed.
    """
    corpus_dir = self.get_target_corpus_dir(target_name)

    os.makedirs(corpus_dir, exist_ok=True)
    # TODO(metzman): Clean up this code.
    project_qualified_fuzz_target_name = target_name
    qualified_name_prefix = self.config.project_name + '_'

    if not target_name.startswith(qualified_name_prefix):
      project_qualified_fuzz_target_name = qualified_name_prefix + target_name

    corpus_url = (f'{utils.GCS_BASE_URL}{self.config.project_name}'
                  '-backup.clusterfuzz-external.appspot.com/corpus/'
                  f'libFuzzer/{project_qualified_fuzz_target_name}/'
                  f'{self.CORPUS_ZIP_NAME}')

    if http_utils.download_and_unpack_zip(corpus_url, corpus_dir):
      return corpus_dir

    return None


class NoClusterFuzzDeployment(BaseClusterFuzzDeployment):
  """ClusterFuzzDeployment implementation used when there is no deployment of
  ClusterFuzz to use."""

  def upload_latest_build(self):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_latest_build."""
    logging.info('Not uploading latest build because no ClusterFuzz '
                 'deployment.')

  def upload_corpus(self, target_name):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_corpus."""
    logging.info('Not uploading corpus because no ClusterFuzz deployment.')

  def upload_crashes(self):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_crashes."""
    logging.info('Not uploading crashes because no ClusterFuzz deployment.')

  def download_corpus(self, target_name):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of download_corpus."""
    logging.info('Not downloading corpus because no ClusterFuzz deployment.')

  def download_latest_build(self):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of download_latest_build."""
    logging.info('Not downloading build because no ClusterFuzz deployment.')


def get_clusterfuzz_deployment(config, workspace):
  """Returns object reprsenting deployment of ClusterFuzz used by |config|."""
  if (config.platform == config.Platform.INTERNAL_GENERIC_CI or
      config.platform == config.Platform.INTERNAL_GITHUB):
    logging.info('Using OSS-Fuzz as ClusterFuzz deployment.')
    return OSSFuzz(config, workspace)
  if config.platform == config.Platform.EXTERNAL_GENERIC_CI:
    logging.info('Not using a ClusterFuzz deployment.')
    return NoClusterFuzzDeployment(config, workspace)
  logging.info('Using ClusterFuzzLite as ClusterFuzz deployment.')
  return ClusterFuzzLite(config, workspace)
