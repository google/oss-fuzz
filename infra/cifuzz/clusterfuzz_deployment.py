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

import config_utils
import continuous_integration
import filestore_utils
import http_utils
import get_coverage
import repo_manager

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


class BaseClusterFuzzDeployment:
  """Base class for ClusterFuzz deployments."""

  def __init__(self, config, workspace):
    self.config = config
    self.workspace = workspace
    self.ci_system = continuous_integration.get_ci(config)

  def download_latest_build(self):
    """Downloads the latest build from ClusterFuzz.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_build(self, commit):
    """Uploads the build with the given commit sha to the filestore."""
    raise NotImplementedError('Child class must implement method.')

  def download_corpus(self, target_name, corpus_dir):
    """Downloads the corpus for |target_name| from ClusterFuzz to |corpus_dir|.

    Returns:
      A path to where the OSS-Fuzz build was stored, or None if it wasn't.
    """
    raise NotImplementedError('Child class must implement method.')

  def upload_crashes(self):
    """Uploads crashes in |crashes_dir| to filestore."""
    raise NotImplementedError('Child class must implement method.')

  def upload_corpus(self, target_name, corpus_dir, replace=False):  # pylint: disable=no-self-use,unused-argument
    """Uploads the corpus for |target_name| to filestore."""
    raise NotImplementedError('Child class must implement method.')

  def upload_coverage(self):
    """Uploads the coverage report to the filestore."""
    raise NotImplementedError('Child class must implement method.')

  def get_coverage(self, repo_path):
    """Returns the project coverage object for the project."""
    raise NotImplementedError('Child class must implement method.')


def _make_empty_dir_if_nonexistent(path):
  """Makes an empty directory at |path| if it does not exist."""
  os.makedirs(path, exist_ok=True)


class ClusterFuzzLite(BaseClusterFuzzDeployment):
  """Class representing a deployment of ClusterFuzzLite."""

  COVERAGE_NAME = 'latest'
  LATEST_BUILD_WINDOW = 3

  def __init__(self, config, workspace):
    super().__init__(config, workspace)
    self.filestore = filestore_utils.get_filestore(self.config)

  def download_latest_build(self):
    if os.path.exists(self.workspace.clusterfuzz_build):
      # This path is necessary because download_latest_build can be called
      # multiple times.That is the case because it is called only when we need
      # to see if a bug is novel, i.e. until we want to check a bug is novel we
      # don't want to waste time calling this, but therefore this method can be
      # called if multiple bugs are found.
      return self.workspace.clusterfuzz_build

    repo_dir = self.ci_system.repo_dir
    if not repo_dir:
      raise RuntimeError('Repo checkout does not exist.')

    _make_empty_dir_if_nonexistent(self.workspace.clusterfuzz_build)
    repo = repo_manager.RepoManager(repo_dir)

    diff_base = self.ci_system.get_diff_base()
    if not diff_base:
      diff_base = 'HEAD^'

    # Builds are stored by commit, so try the latest |LATEST_BUILD_WINDOW|
    # commits before the current diff base.
    # TODO(ochang): If API usage becomes an issue, this can be optimized by the
    # filestore accepting a list of filenames to try.
    for old_commit in repo.get_commit_list(diff_base,
                                           limit=self.LATEST_BUILD_WINDOW):
      logging.info('Trying to downloading previous build %s.', old_commit)
      build_name = self._get_build_name(old_commit)
      try:
        if self.filestore.download_build(build_name,
                                         self.workspace.clusterfuzz_build):
          logging.info('Done downloading previous build.')
          return self.workspace.clusterfuzz_build

        logging.info('Build for %s does not exist.', old_commit)
      except Exception as err:  # pylint: disable=broad-except
        logging.error('Could not download build for %s because of: %s',
                      old_commit, err)

    return None

  def download_corpus(self, target_name, corpus_dir):
    _make_empty_dir_if_nonexistent(corpus_dir)
    logging.info('Downloading corpus for %s to %s.', target_name, corpus_dir)
    corpus_name = self._get_corpus_name(target_name)
    try:
      self.filestore.download_corpus(corpus_name, corpus_dir)
      logging.info('Done downloading corpus. Contains %d elements.',
                   len(os.listdir(corpus_dir)))
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Failed to download corpus for target: %s. Error: %s',
                    target_name, str(err))
    return corpus_dir

  def _get_build_name(self, name):
    return f'{self.config.sanitizer}-{name}'

  def _get_corpus_name(self, target_name):  # pylint: disable=no-self-use
    """Returns the name of the corpus artifact."""
    return target_name

  def upload_corpus(self, target_name, corpus_dir, replace=False):
    """Upload the corpus produced by |target_name|."""
    logging.info('Uploading corpus in %s for %s.', corpus_dir, target_name)
    name = self._get_corpus_name(target_name)
    try:
      self.filestore.upload_corpus(name, corpus_dir, replace=replace)
      logging.info('Done uploading corpus.')
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Failed to upload corpus for target: %s. Error: %s.',
                    target_name, err)

  def upload_build(self, commit):
    """Upload the build produced by CIFuzz as the latest build."""
    logging.info('Uploading latest build in %s.', self.workspace.out)
    build_name = self._get_build_name(commit)
    try:
      result = self.filestore.upload_build(build_name, self.workspace.out)
      logging.info('Done uploading latest build.')
      return result
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Failed to upload latest build: %s. Error: %s',
                    self.workspace.out, err)

  def upload_crashes(self):
    """Uploads crashes."""
    artifact_dirs = os.listdir(self.workspace.artifacts)
    if not artifact_dirs:
      logging.info('No crashes in %s. Not uploading.', self.workspace.artifacts)
      return

    for crash_target in artifact_dirs:
      artifact_dir = os.path.join(self.workspace.artifacts, crash_target)
      if not os.path.isdir(artifact_dir):
        logging.warning('%s is not an expected artifact directory, skipping.',
                        crash_target)
        continue

      logging.info('Uploading crashes in %s.', artifact_dir)
      try:
        self.filestore.upload_crashes(crash_target, artifact_dir)
        logging.info('Done uploading crashes.')
      except Exception as err:  # pylint: disable=broad-except
        logging.error('Failed to upload crashes. Error: %s', err)

  def upload_coverage(self):
    """Uploads the coverage report to the filestore."""
    self.filestore.upload_coverage(self.COVERAGE_NAME,
                                   self.workspace.coverage_report)

  def get_coverage(self, repo_path):
    """Returns the project coverage object for the project."""
    _make_empty_dir_if_nonexistent(self.workspace.clusterfuzz_coverage)
    try:
      if not self.filestore.download_coverage(
          self.COVERAGE_NAME, self.workspace.clusterfuzz_coverage):
        logging.error('Could not download coverage.')
        return None
      return get_coverage.FilesystemCoverage(
          repo_path, self.workspace.clusterfuzz_coverage)
    except Exception as err:  # pylint: disable=broad-except
      logging.error('Could not get coverage: %s.', err)
      return None


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
    version_file = (
        f'{self.config.oss_fuzz_project_name}-{self.config.sanitizer}'
        '-latest.version')
    version_url = utils.url_join(utils.GCS_BASE_URL, self.CLUSTERFUZZ_BUILDS,
                                 self.config.oss_fuzz_project_name,
                                 version_file)
    try:
      response = urllib.request.urlopen(version_url)
    except urllib.error.HTTPError:
      logging.error('Error getting latest build version for %s from: %s.',
                    self.config.oss_fuzz_project_name, version_url)
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

    _make_empty_dir_if_nonexistent(self.workspace.clusterfuzz_build)

    latest_build_name = self.get_latest_build_name()
    if not latest_build_name:
      return None

    logging.info('Downloading latest build.')
    oss_fuzz_build_url = utils.url_join(utils.GCS_BASE_URL,
                                        self.CLUSTERFUZZ_BUILDS,
                                        self.config.oss_fuzz_project_name,
                                        latest_build_name)
    if http_utils.download_and_unpack_zip(oss_fuzz_build_url,
                                          self.workspace.clusterfuzz_build):
      logging.info('Done downloading latest build.')
      return self.workspace.clusterfuzz_build

    return None

  def upload_build(self, commit):  # pylint: disable=no-self-use
    """Noop Implementation of upload_build."""
    logging.info('Not uploading latest build because on OSS-Fuzz.')

  def upload_corpus(self, target_name, corpus_dir, replace=False):  # pylint: disable=no-self-use,unused-argument
    """Noop Implementation of upload_corpus."""
    logging.info('Not uploading corpus because on OSS-Fuzz.')

  def upload_crashes(self):  # pylint: disable=no-self-use
    """Noop Implementation of upload_crashes."""
    logging.info('Not uploading crashes because on OSS-Fuzz.')

  def download_corpus(self, target_name, corpus_dir):
    """Downloads the latest OSS-Fuzz corpus for the target.

    Returns:
      The local path to to corpus or None if download failed.
    """
    _make_empty_dir_if_nonexistent(corpus_dir)
    project_qualified_fuzz_target_name = target_name
    qualified_name_prefix = self.config.oss_fuzz_project_name + '_'
    if not target_name.startswith(qualified_name_prefix):
      project_qualified_fuzz_target_name = qualified_name_prefix + target_name

    corpus_url = (f'{utils.GCS_BASE_URL}{self.config.oss_fuzz_project_name}'
                  '-backup.clusterfuzz-external.appspot.com/corpus/'
                  f'libFuzzer/{project_qualified_fuzz_target_name}/'
                  f'{self.CORPUS_ZIP_NAME}')
    logging.info('Downloading corpus from OSS-Fuzz: %s', corpus_url)

    if not http_utils.download_and_unpack_zip(corpus_url, corpus_dir):
      logging.warning('Failed to download corpus for %s.', target_name)
    return corpus_dir

  def upload_coverage(self):
    """Noop Implementation of upload_coverage_report."""
    logging.info('Not uploading coverage report because on OSS-Fuzz.')

  def get_coverage(self, repo_path):
    """Returns the project coverage object for the project."""
    try:
      return get_coverage.OSSFuzzCoverage(repo_path,
                                          self.config.oss_fuzz_project_name)
    except get_coverage.CoverageError:
      return None


class NoClusterFuzzDeployment(BaseClusterFuzzDeployment):
  """ClusterFuzzDeployment implementation used when there is no deployment of
  ClusterFuzz to use."""

  def upload_build(self, commit):  # pylint: disable=no-self-use
    """Noop Implementation of upload_build."""
    logging.info('Not uploading latest build because no ClusterFuzz '
                 'deployment.')

  def upload_corpus(self, target_name, corpus_dir, replace=False):  # pylint: disable=no-self-use,unused-argument
    """Noop Implementation of upload_corpus."""
    logging.info('Not uploading corpus because no ClusterFuzz deployment.')

  def upload_crashes(self):  # pylint: disable=no-self-use
    """Noop Implementation of upload_crashes."""
    logging.info('Not uploading crashes because no ClusterFuzz deployment.')

  def download_corpus(self, target_name, corpus_dir):
    """Noop Implementation of download_corpus."""
    logging.info('Not downloading corpus because no ClusterFuzz deployment.')
    return _make_empty_dir_if_nonexistent(corpus_dir)

  def download_latest_build(self):  # pylint: disable=no-self-use
    """Noop Implementation of download_latest_build."""
    logging.info(
        'Not downloading latest build because no ClusterFuzz deployment.')

  def upload_coverage(self):
    """Noop Implementation of upload_coverage."""
    logging.info(
        'Not uploading coverage report because no ClusterFuzz deployment.')

  def get_coverage(self, repo_path):
    """Noop Implementation of get_coverage."""
    logging.info(
        'Not getting project coverage because no ClusterFuzz deployment.')


_PLATFORM_CLUSTERFUZZ_DEPLOYMENT_MAPPING = {
    config_utils.BaseConfig.Platform.INTERNAL_GENERIC_CI: OSSFuzz,
    config_utils.BaseConfig.Platform.INTERNAL_GITHUB: OSSFuzz,
    config_utils.BaseConfig.Platform.EXTERNAL_GENERIC_CI: ClusterFuzzLite,
    config_utils.BaseConfig.Platform.EXTERNAL_GITHUB: ClusterFuzzLite,
}


def get_clusterfuzz_deployment(config, workspace):
  """Returns object reprsenting deployment of ClusterFuzz used by |config|."""
  deployment_cls = _PLATFORM_CLUSTERFUZZ_DEPLOYMENT_MAPPING[config.platform]
  if config.no_clusterfuzz_deployment:
    logging.info('Overriding ClusterFuzzDeployment. Using None.')
    deployment_cls = NoClusterFuzzDeployment
  result = deployment_cls(config, workspace)
  logging.info('ClusterFuzzDeployment: %s.', result)
  return result
