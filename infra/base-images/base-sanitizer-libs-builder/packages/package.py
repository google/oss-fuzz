#!/usr/bin/env python
# Copyright 2017 Google Inc.
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
#
################################################################################

import os
import subprocess

import apt

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


def ApplyPatch(source_directory, patch_name):
  """Apply custom patch."""
  subprocess.check_call(['patch', '-p1', '-i',
                         os.path.join(SCRIPT_DIR, patch_name)],
                        cwd=source_directory)


class PackageException(Exception):
  """Base package exception."""


class Package(object):
  """Base package."""

  def __init__(self, name, apt_version):
    self.name = name
    self.apt_version = apt_version

  def PreBuild(self, source_directory, env, custom_bin_dir):
    return

  def PostBuild(self, source_directory, env, custom_bin_dir):
    return

  def PreDownload(self, download_directory):
    return

  def PostDownload(self, source_directory):
    return

  def InstallBuildDeps(self):
    """Install build dependencies for a package."""
    subprocess.check_call(['apt-get', 'update'])
    subprocess.check_call(['apt-get', 'build-dep', '-y', self.name])

    # Reload package after update.
    self.apt_version = (
        apt.Cache()[self.apt_version.package.name].candidate)

  def DownloadSource(self, download_directory):
    """Download the source for a package."""
    self.PreDownload(download_directory)

    source_directory = self.apt_version.fetch_source(download_directory)

    self.PostDownload(source_directory)
    return source_directory

  def Build(self, source_directory, env, custom_bin_dir):
    """Build .deb packages."""
    self.PreBuild(source_directory, env, custom_bin_dir)
    subprocess.check_call(
        ['dpkg-buildpackage', '-us', '-uc', '-B'],
        cwd=source_directory, env=env)
    self.PostBuild(source_directory, env, custom_bin_dir)


