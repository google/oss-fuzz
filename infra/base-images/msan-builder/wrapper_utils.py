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

import contextlib
import os
import subprocess


def DpkgHostArchitecture():
  """Return the host architecture."""
  return subprocess.check_output(
      ['dpkg-architecture', '-qDEB_HOST_GNU_TYPE']).strip()


def InstallWrapper(bin_dir, name, contents, extra_names=None):
  """Install a custom wrapper script into |bin_dir|."""
  path = os.path.join(bin_dir, name)
  with open(path, 'w') as f:
    f.write(contents)

  os.chmod(path, 0755)

  if extra_names:
    CreateSymlinks(path, bin_dir, extra_names)


def CreateSymlinks(original_path, bin_dir, extra_names):
  """Create symlinks."""
  for extra_name in extra_names:
    extra_path = os.path.join(bin_dir, extra_name)
    os.symlink(original_path, extra_path)
