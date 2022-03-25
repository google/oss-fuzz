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
"""Module for a generic filestore."""


class FilestoreError(Exception):
  """Error using the filestore."""


# pylint: disable=unused-argument,no-self-use
class BaseFilestore:
  """Base class for a filestore."""

  def __init__(self, config):
    self.config = config

  def upload_crashes(self, name, directory):
    """Uploads the crashes at |directory| to |name|."""
    raise NotImplementedError('Child class must implement method.')

  def upload_corpus(self, name, directory, replace=False):
    """Uploads the corpus at |directory| to |name|."""
    raise NotImplementedError('Child class must implement method.')

  def upload_build(self, name, directory):
    """Uploads the build at |directory| to |name|."""
    raise NotImplementedError('Child class must implement method.')

  def upload_coverage(self, name, directory):
    """Uploads the coverage report at |directory| to |name|."""
    raise NotImplementedError('Child class must implement method.')

  def download_corpus(self, name, dst_directory):
    """Downloads the corpus located at |name| to |dst_directory|."""
    raise NotImplementedError('Child class must implement method.')

  def download_build(self, name, dst_directory):
    """Downloads the build with |name| to |dst_directory|."""
    raise NotImplementedError('Child class must implement method.')

  def download_coverage(self, name, dst_directory):
    """Downloads the latest project coverage report."""
    raise NotImplementedError('Child class must implement method.')
