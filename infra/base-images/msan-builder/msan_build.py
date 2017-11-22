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
import argparse
import os
import shutil
import subprocess
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__)) 

class MSanBuildException(Exception):
  """Base exception."""


def SetUpEnvironment(work_dir):
  """Set up build environment."""
  env = {}
  env['REAL_CLANG_PATH'] = subprocess.check_output(['which', 'clang']).strip()
  print('Real clang at', env['REAL_CLANG_PATH'])
  compiler_wrapper_path = os.path.join(SCRIPT_DIR, 'compiler_wrapper.py')

  # Symlink binaries into TMP/bin
  bin_dir = os.path.join(work_dir, 'bin')
  os.mkdir(bin_dir)

  os.symlink(compiler_wrapper_path,
             os.path.join(bin_dir, 'clang'))

  os.symlink(compiler_wrapper_path,
             os.path.join(bin_dir, 'clang++'))

  env['CC'] = os.path.join(bin_dir, 'clang')
  env['CXX'] = os.path.join(bin_dir, 'clang++')

  # Not all build rules respect $CC/$CXX, so make additional symlinks.
  dpkg_host_architecture = subprocess.check_output(
      ['dpkg-architecture', '-qDEB_HOST_GNU_TYPE']).strip()
  os.symlink(compiler_wrapper_path,
             os.path.join(bin_dir, dpkg_host_architecture + '-gcc'))
  os.symlink(compiler_wrapper_path,
             os.path.join(bin_dir, dpkg_host_architecture + '-g++'))

  os.symlink(compiler_wrapper_path, os.path.join(bin_dir, 'gcc'))
  os.symlink(compiler_wrapper_path, os.path.join(bin_dir, 'cc'))
  os.symlink(compiler_wrapper_path, os.path.join(bin_dir, 'g++'))
  os.symlink(compiler_wrapper_path, os.path.join(bin_dir, 'c++'))

  MSAN_OPTIONS = (
      '-fsanitize=memory -fsanitize-memory-track-origins=2 '
      '-fsanitize-recover=memory -fPIC -fno-omit-frame-pointer')

  env['DEB_BUILD_OPTIONS'] = 'nocheck'
  env['DEB_CFLAGS_APPEND'] = MSAN_OPTIONS
  env['DEB_CXXFLAGS_APPEND'] = MSAN_OPTIONS + ' -stdlib=libc++'
  env['DEB_CPPFLAGS_APPEND'] = env['DEB_CXXFLAGS_APPEND']
  env['DEB_LDFLAGS_APPEND'] = MSAN_OPTIONS
  env['DPKG_GENSYMBOLS_CHECK_LEVEL'] = '0'

  env['PATH'] = bin_dir + ':' + os.environ['PATH']

  # Prevent entire build from failing because of bugs/uninstrumented in tools
  # that are part of the build.
  # TODO(ochang): Figure out some way to suppress reports since they can still
  # be very noisy.
  env['MSAN_OPTIONS'] = 'halt_on_error=0:exitcode=0'
  return env


def InstallBuildDeps(package_name):
  """Install build dependencies for a package."""
  subprocess.check_call(['apt-get', 'build-dep', '-y', package_name])


def DownloadPackageSource(package_name, download_directory):
  """Download the source for a package."""
  before = FindDirs(download_directory)
  subprocess.check_call(
      ['apt-get', 'source', package_name],
      stderr=subprocess.STDOUT, cwd=download_directory)

  after = FindDirs(download_directory)
  new_dirs = [subdir for subdir in after
              if subdir not in before]

  if len(new_dirs) != 1:
    raise MSanBuildException(
        'Found more than one new directory after downloading apt-get source.')

  return os.path.join(download_directory, new_dirs[0])


def FindDirs(directory):
  """Find sub directories."""
  return [subdir for subdir in os.listdir(directory)
          if os.path.isdir(os.path.join(directory, subdir))]


def BuildDebianPackage(source_directory, env):
  """Build .deb packages."""
  subprocess.check_call(
      ['dpkg-buildpackage', '-us', '-uc', '-b'], cwd=source_directory, env=env)


def ExtractSharedLibraries(work_directory, output_directory):
  """Extract all shared libraries from .deb packages."""
  extract_directory = os.path.join(work_directory, 'extracted')
  os.mkdir(extract_directory)

  for filename in os.listdir(work_directory):
    file_path = os.path.join(work_directory, filename)
    if not file_path.endswith('.deb'):
      continue

    subprocess.check_call(['dpkg-deb', '-x', file_path, extract_directory])

  for root, _, filenames in os.walk(extract_directory):
    for filename in filenames:
      file_path = os.path.join(root, filename)
      if os.path.isfile(file_path) and file_path.endswith('.so'):
        shutil.copy2(file_path, output_directory)


class MSanBuilder(object):
  """MSan builder."""

  def __init__(self, debug=False):
    self.debug = debug
    self.work_dir = None
    self.env = None

  def __enter__(self):
    self.work_dir = tempfile.mkdtemp()
    self.env = SetUpEnvironment(self.work_dir)
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    if not debug:
      shutil.rmtree(self.work_dir, ignore_errors=True)

  def build(self, package_name, output_directory):
    """Build the package and write results into the output directory."""
    InstallBuildDeps(package_name)
    source_directory = DownloadPackageSource(package_name, self.work_dir)
    print('Source downloaded to', source_directory)

    BuildDebianPackage(source_directory, self.env)
    ExtractSharedLibraries(self.work_dir, output_directory)


def main():
  parser = argparse.ArgumentParser('msan_build.py', description='MSan builder.')
  parser.add_argument('package_name', help='Name of the package.')
  parser.add_argument('output_dir', help='Output directory.')
  parser.add_argument('--debug', action='store_true', help='Enable debug mode.')

  args = parser.parse_args()

  if not os.path.exists(args.output_dir):
    os.makedirs(args.output_dir)

  with MSanBuilder(debug=args.debug) as builder:
    builder.build(args.package_name, args.output_dir)


if __name__ == '__main__':
  main()

