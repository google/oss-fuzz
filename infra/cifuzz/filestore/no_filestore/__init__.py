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
"""Empty filestore implementation for platforms that haven't implemented it."""
import logging

import filestore

# pylint:disable=no-self-use,unused-argument


class NoFilestore(filestore.BaseFilestore):
  """Empty Filestore implementation."""

  def upload_crashes(self, name, directory):
    """Noop implementation of upload_crashes."""
    logging.info('Not uploading crashes because no Filestore.')

  def upload_corpus(self, name, directory, replace=False):
    """Noop implementation of upload_corpus."""
    logging.info('Not uploading corpus because no Filestore.')

  def upload_build(self, name, directory):
    """Noop implementation of upload_build."""
    logging.info('Not uploading build because no Filestore.')

  def upload_coverage(self, name, directory):
    """Noop implementation of upload_coverage."""
    logging.info('Not uploading coverage because no Filestore.')

  def download_corpus(self, name, dst_directory):
    """Noop implementation of download_corpus."""
    logging.info('Not downloading corpus because no Filestore.')

  def download_build(self, name, dst_directory):
    """Noop implementation of download_build."""
    logging.info('Not downloading build because no Filestore.')

  def download_coverage(self, name, dst_directory):
    """Noop implementation of download_coverage."""
    logging.info('Not downloading coverage because no Filestore.')
