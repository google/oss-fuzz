import posixpath
import threading

# TODO(metzman): Don't rely on internal code.
from clusterfuzz._internal.system import gsutil

import filestore

# Thread-local global variables.
_local = threading.local()

def _create_runnner():
  _local.runner = gsutil.GSUtilRunner()

def _runner():
  if getattr(_local, 'runner', None) is None:
    _create_runner()
  return _local.runner


class GSUtilFilestore(filestore.BaseFilestore):
  BUILD_DIR = 'build'
  CRASHES_DIR = 'crashes'
  CORPUS_DIR = 'corpus'
  COVERAGE_DIR = 'coverage'

  def __init__(self, config):
    super().__init__(config)
    self._runner = _runner()
    self._cloud_bucket = self.config.cloud_bucket

  def get_gsutil_url(name, prefix):
    if not prefix:
      return posixpath.join(self._cloud_bucket, name)
    return posixpath.join(self._cloud_bucket, prefix, name)

  def _upload_directory(self, name, directory, prefix, delete=False):
    gsutil_url = self.get_gsutil_url(name, prefix)
    return self._runner.rsync(directory, gsutil_url, delete=delete)

  def _download_directory(self, name, dst_directory, prefix):
    gsutil_url = self.get_gsutil_url(name, prefix)
    return self._runner.rsync(gsutil_url, dst_directory)

  def upload_crashes(self, name, directory):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(name, directory, self.CRASHES_DIR)

  def upload_corpus(self, name, directory, replace=False):
    """Uploads the crashes at |directory| to |name|."""
    return self._upload_directory(
        directory, gsutil_url, self.CORPUS_DIR, delete=replace)

  def upload_build(self, name, directory):
    """Uploads the build located at |directory| to |name|."""
    return self._upload_directory(name, directory, self.BUILD_DIR)

  def upload_coverage(self, name, directory):
    """Uploads the coverage report at |directory| to |name|."""
    return self._upload_directory(name, directory, self.COVERAGE_DIR)

  def download_corpus(self, name, dst_directory):
    """Downloads the corpus located at |name| to |dst_directory|."""
    return self._download_directory(name, dst_directory, self.CORPUS_DIR)

  def download_build(self, name, dst_directory):
    """Downloads the build with |name| to |dst_directory|."""
    return self._download_directory(name, dst_directory, self.BUILD_DIR)

  def download_coverage(self, dst_directory):
    """Downloads the latest project coverage report."""
    return self._download_directory(name, dst_directory, self.COVERAGE_DIR)
