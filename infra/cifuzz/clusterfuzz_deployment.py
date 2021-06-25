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

import filestore_utils

import http_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


class BaseClusterFuzzDeployment:
  """Base class for ClusterFuzz deployments."""

  CORPUS_DIR_NAME = 'cifuzz-corpus'
  BUILD_DIR_NAME = 'cifuzz-latest-build'

  def __init__(self, config):
    self.config = config

  def download_latest_build(self, parent_dir):
    """Downloads the latest build from ClusterFuzz.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_latest_build(self, build_dir):
    """Uploads the latest build to the filestore.
    Returns:
      True on success.
    """
    raise NotImplementedError('Child class must implement method.')

  def download_corpus(self, target_name, parent_dir):
    """Downloads the corpus for |target_name| from ClusterFuzz to a subdirectory
    of |parent_dir|.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_crashes(self, crashes_dir):
    """Uploads crashes in |crashes_dir| to filestore."""
    raise NotImplementedError('Child class must implement method.')

  def get_target_corpus_dir(self, target_name, parent_dir):
    """Returns the path to the corpus dir for |target_name| within
    |parent_dir|."""
    return os.path.join(self.get_corpus_dir(parent_dir), target_name)

  def get_corpus_dir(self, parent_dir):
    """Returns the path to the corpus dir within |parent_dir|."""
    return os.path.join(parent_dir, self.CORPUS_DIR_NAME)

  def get_build_dir(self, parent_dir):
    """Returns the path to the build dir for within |parent_dir|."""
    return os.path.join(parent_dir, self.BUILD_DIR_NAME)

  def upload_corpus(self, target_name, corpus_dir):  # pylint: disable=no-self-use,unused-argument
    """Uploads the corpus for |target_name| in |corpus_dir| to filestore."""
    raise NotImplementedError('Child class must implement method.')

  def make_empty_corpus_dir(self, target_name, parent_dir):
    """Makes an empty corpus directory for |target_name| in |parent_dir| and
    returns the path to the directory."""
    corpus_dir = self.get_target_corpus_dir(target_name, parent_dir)
    os.makedirs(corpus_dir, exist_ok=True)
    return corpus_dir


class ClusterFuzzLite(BaseClusterFuzzDeployment):
  """Class representing a deployment of ClusterFuzzLite."""

  BASE_BUILD_NAME = 'cifuzz-build-'

  def __init__(self, config):
    super().__init__(config)
    self.filestore = filestore_utils.get_filestore(self.config)

  def download_latest_build(self, parent_dir):
    build_dir = self.get_build_dir(parent_dir)
    if os.path.exists(build_dir):
      # This path is necessary because download_latest_build can be called
      # multiple times.That is the case because it is called only when we need
      # to see if a bug is novel, i.e. until we want to check a bug is novel we
      # don't want to waste time calling this, but therefore this method can be
      # called if multiple bugs are found.
      return build_dir

    os.makedirs(build_dir, exist_ok=True)
    build_name = self._get_build_name()

    try:
      if self.filestore.download_latest_build(build_name, build_dir):
        return build_dir
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Could not download latest build because of: %s.', err)

    return None

  def download_corpus(self, target_name, parent_dir):
    corpus_dir = self.make_empty_corpus_dir(target_name, parent_dir)
    logging.debug('ClusterFuzzLite: downloading corpus for %s to %s.',
                  target_name, parent_dir)
    corpus_name = self._get_corpus_name(target_name)
    try:
      self.filestore.download_corpus(corpus_name, corpus_dir)
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Failed to download corpus for target: %s. Error: %s.',
                    target_name, str(err))
    return corpus_dir

  def _get_build_name(self):
    return self.BASE_BUILD_NAME + self.config.sanitizer

  def _get_corpus_name(self, target_name):  # pylint: disable=no-self-use
    """Returns the name of the corpus artifact."""
    return 'corpus-{target_name}'.format(target_name=target_name)

  def _get_crashes_artifact_name(self):  # pylint: disable=no-self-use
    """Returns the name of the crashes artifact."""
    return 'crashes'

  def upload_corpus(self, target_name, corpus_dir):
    """Upload the corpus produced by |target_name| in |corpus_dir|."""
    logging.info('Uploading corpus in %s for %s.', corpus_dir, target_name)
    name = self._get_corpus_name(target_name)
    try:
      self.filestore.upload_directory(name, corpus_dir)
    except Exception as error:  # pylint: disable=broad-except
      logging.error('Failed to upload corpus for target: %s. Error: %s.',
                    target_name, error)

  def upload_latest_build(self, build_dir):
    logging.info('Uploading latest build in %s.', build_dir)
    build_name = self._get_build_name()
    try:
      return self.filestore.upload_directory(build_name, build_dir)
    except Exception as error:  # pylint: disable=broad-except
      logging.error('Failed to upload latest build: %s. Error: %s.', build_dir,
                    error)

  def upload_crashes(self, crashes_dir):
    if not os.listdir(crashes_dir):
      logging.info('No crashes in %s. Not uploading.', crashes_dir)
      return

    crashes_artifact_name = self._get_crashes_artifact_name()

    logging.info('Uploading crashes in %s', crashes_dir)
    try:
      self.filestore.upload_directory(crashes_artifact_name, crashes_dir)
    except Exception as error:  # pylint: disable=broad-except
      logging.error('Failed to upload crashes. Error: %s.', error)


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

  def download_latest_build(self, parent_dir):
    """Downloads the latest OSS-Fuzz build from GCS.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    build_dir = self.get_build_dir(parent_dir)
    if os.path.exists(build_dir):
      # This function can be called multiple times, don't download the build
      # again.
      return build_dir

    os.makedirs(build_dir, exist_ok=True)

    latest_build_name = self.get_latest_build_name()
    if not latest_build_name:
      return None

    oss_fuzz_build_url = utils.url_join(utils.GCS_BASE_URL,
                                        self.CLUSTERFUZZ_BUILDS,
                                        self.config.project_name,
                                        latest_build_name)
    if http_utils.download_and_unpack_zip(oss_fuzz_build_url, build_dir):
      return build_dir

    return None

  def upload_latest_build(self, build_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_latest_build."""
    logging.info('Not uploading latest build because on OSS-Fuzz.')

  def upload_corpus(self, target_name, corpus_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_corpus."""
    logging.info('Not uploading corpus because on OSS-Fuzz.')

  def upload_crashes(self, crashes_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_crashes."""
    logging.info('Not uploading crashes because on OSS-Fuzz.')

  def download_corpus(self, target_name, parent_dir):
    """Downloads the latest OSS-Fuzz corpus for the target.

    Returns:
      The local path to to corpus or None if download failed.
    """
    corpus_dir = self.make_empty_corpus_dir(target_name, parent_dir)
    project_qualified_fuzz_target_name = target_name
    qualified_name_prefix = self.config.project_name + '_'
    if not target_name.startswith(qualified_name_prefix):
      project_qualified_fuzz_target_name = qualified_name_prefix + target_name

    corpus_url = (f'{utils.GCS_BASE_URL}{self.config.project_name}'
                  '-backup.clusterfuzz-external.appspot.com/corpus/'
                  f'libFuzzer/{project_qualified_fuzz_target_name}/'
                  f'{self.CORPUS_ZIP_NAME}')

    if not http_utils.download_and_unpack_zip(corpus_url, corpus_dir):
      logging.warning('Failed to download corpus for %s.', target_name)
    return corpus_dir


class NoClusterFuzzDeployment(BaseClusterFuzzDeployment):
  """ClusterFuzzDeployment implementation used when there is no deployment of
  ClusterFuzz to use."""

  def upload_latest_build(self, build_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_latest_build."""
    logging.info('Not uploading latest build because no ClusterFuzz '
                 'deployment.')

  def upload_corpus(self, target_name, corpus_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_corpus."""
    logging.info('Not uploading corpus because no ClusterFuzz deployment.')

  def upload_crashes(self, crashes_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of upload_crashes."""
    logging.info('Not uploading crashes because no ClusterFuzz deployment.')

  def download_corpus(self, target_name, parent_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of download_corpus."""
    logging.info('Not downloading corpus because no ClusterFuzz deployment.')
    return self.make_empty_corpus_dir(target_name, parent_dir)

  def download_latest_build(self, parent_dir):  # pylint: disable=no-self-use,unused-argument
    """Noop Impelementation of download_latest_build."""
    logging.info(
        'Not downloading latest build because no ClusterFuzz deployment.')


def get_clusterfuzz_deployment(config):
  """Returns object reprsenting deployment of ClusterFuzz used by |config|."""
  if (config.platform == config.Platform.INTERNAL_GENERIC_CI or
      config.platform == config.Platform.INTERNAL_GITHUB):
    logging.info('Using OSS-Fuzz as ClusterFuzz deployment.')
    return OSSFuzz(config)
  if config.platform == config.Platform.EXTERNAL_GENERIC_CI:
    logging.info('Not using a ClusterFuzz deployment.')
    return NoClusterFuzzDeployment(config)
  logging.info('Using ClusterFuzzLite as ClusterFuzz deployment.')
  return ClusterFuzzLite(config)
