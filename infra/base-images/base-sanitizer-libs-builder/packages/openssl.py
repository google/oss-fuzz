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
"""
openssl.py
"""
import os
import shutil

import package


def add_no_asm_arg(config_path):
  """Add --no-asm to config scripts."""
  shutil.move(config_path, config_path + '.real')
  with open(config_path, 'w') as out_file:
    out_file.write('#!/bin/sh\n' '%s.real no-asm "$@"\n' % config_path)
  os.chmod(config_path, 0o755)


class Package(package.Package):  # pylint: disable=too-few-public-methods
  """openssl package."""

  def __init__(self, apt_version):
    super(Package, self).__init__('openssl', apt_version)

  # pylint: disable=no-self-use,unused-argument
  def pre_build(self, source_directory, env, custom_bin_dir):
    """ pre_build() """
    add_no_asm_arg(os.path.join(source_directory, 'Configure'))
    add_no_asm_arg(os.path.join(source_directory, 'config'))
