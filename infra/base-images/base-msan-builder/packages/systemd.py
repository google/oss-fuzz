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

from __future__ import print_function
import glob
import os
import subprocess

import package
import wrapper_utils


class Package(package.Package):
  """systemd package."""

  def __init__(self, apt_version):
    super(Package, self).__init__('systemd', apt_version)

  def PreBuild(self, source_directory, env, custom_bin_dir):
    # Hide msan symbols from nm. the systemd build system uses this to find
    # undefined symbols and errors out if it does.
    nm_wrapper = (
        '#!/bin/bash\n'
        '/usr/bin/nm "$@" | grep -E -v "U (__msan|memset)"\n'
        'exit ${PIPESTATUS[0]}\n')

    wrapper_utils.InstallWrapper(custom_bin_dir, 'nm', nm_wrapper,
                                 [wrapper_utils.DpkgHostArchitecture() + '-nm'])
