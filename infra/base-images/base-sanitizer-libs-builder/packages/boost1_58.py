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
"""Custom options for boost1.58."""
import package


class Package(package.Package):  # pylint: disable=too-few-public-methods
  """boost1.58 package."""

  def __init__(self, apt_version):
    super(Package, self).__init__('boost1.58', apt_version)

  def pre_build(self, _source_directory, env, _custom_bin_dir):  # pylint: disable=no-self-use
    """Pre-build configuration for boost1.58."""
    # Otherwise py_nonblocking.cpp fails to build.
    env['DEB_CXXFLAGS_APPEND'] += ' -std=c++98'
