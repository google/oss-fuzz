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
import imp
import os
import multiprocessing
import resource
import shutil
import subprocess
import tempfile

import apt
from apt import debfile

from packages import package
import wrapper_utils

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PACKAGES_DIR = os.path.join(SCRIPT_DIR, 'packages')

TRACK_ORIGINS_ARG = '-fsanitize-memory-track-origins='

INJECTED_ARGS = [
    '-fsanitize=memory',
    '-fsanitize-recover=memory',
    '-fPIC',
    '-fno-omit-frame-pointer',
]


class MSanBuildException(Exception):
  """Base exception."""


def GetTrackOriginsFlag():
  """Get the track origins flag."""
  if os.getenv('MSAN_NO_TRACK_ORIGINS'):
    return TRACK_ORIGINS_ARG + '0'

  return TRACK_ORIGINS_ARG + '2'


def GetInjectedFlags():
  return INJECTED_ARGS + [GetTrackOriginsFlag()]


def SetUpEnvironment(work_dir):
  """Set up build environment."""
  env = {}
  env['REAL_CLANG_PATH'] = subprocess.check_output(['which', 'clang']).strip()
  print('Real clang at', env['REAL_CLANG_PATH'])
  compiler_wrapper_path = os.path.join(SCRIPT_DIR, 'compiler_wrapper.py')

  # Symlink binaries into TMP/bin
  bin_dir = os.path.join(work_dir, 'bin')
  os.mkdir(bin_dir)

  dpkg_host_architecture = wrapper_utils.DpkgHostArchitecture()
  wrapper_utils.CreateSymlinks(
      compiler_wrapper_path, bin_dir, [
          'clang',
          'clang++',
          # Not all build rules respect $CC/$CXX, so make additional symlinks.
          'gcc',
          'g++',
          'cc',
          'c++',
          dpkg_host_architecture + '-gcc',
          dpkg_host_architecture + '-g++',
      ])

  env['CC'] = os.path.join(bin_dir, 'clang')
  env['CXX'] = os.path.join(bin_dir, 'clang++')

  MSAN_OPTIONS = ' '.join(GetInjectedFlags())

  # We don't use nostrip because some build rules incorrectly break when it is
  # passed. Instead we install our own no-op strip binaries.
  env['DEB_BUILD_OPTIONS'] = ('nocheck parallel=%d' %
                              multiprocessing.cpu_count())
  env['DEB_CFLAGS_APPEND'] = MSAN_OPTIONS
  env['DEB_CXXFLAGS_APPEND'] = MSAN_OPTIONS + ' -stdlib=libc++'
  env['DEB_CPPFLAGS_APPEND'] = MSAN_OPTIONS
  env['DEB_LDFLAGS_APPEND'] = MSAN_OPTIONS
  env['DPKG_GENSYMBOLS_CHECK_LEVEL'] = '0'

  # debian/rules can set DPKG_GENSYMBOLS_CHECK_LEVEL explicitly, so override it.
  gen_symbols_wrapper = (
        '#!/bin/sh\n'
        'export DPKG_GENSYMBOLS_CHECK_LEVEL=0\n'
        '/usr/bin/dpkg-gensymbols "$@"\n')

  wrapper_utils.InstallWrapper(bin_dir, 'dpkg-gensymbols',
                               gen_symbols_wrapper)

  # Install no-op strip binaries.
  no_op_strip = ('#!/bin/sh\n'
                 'exit 0\n')
  wrapper_utils.InstallWrapper(
      bin_dir, 'strip', no_op_strip,
      [dpkg_host_architecture + '-strip'])

  env['PATH'] = bin_dir + ':' + os.environ['PATH']

  # nocheck doesn't disable override_dh_auto_test. So we have this hack to try
  # to disable "make check" or "make test" invocations.
  make_wrapper = (
      '#!/bin/bash\n'
      'if [ "$1" = "test" ] || [ "$1" = "check" ]; then\n'
      '  exit 0\n'
      'fi\n'
      '/usr/bin/make "$@"\n')
  wrapper_utils.InstallWrapper(bin_dir, 'make',
                               make_wrapper)

  # Prevent entire build from failing because of bugs/uninstrumented in tools
  # that are part of the build.
  msan_log_dir = os.path.join(work_dir, 'msan')
  os.mkdir(msan_log_dir)
  msan_log_path = os.path.join(msan_log_dir, 'log')
  env['MSAN_OPTIONS'] = (
      'halt_on_error=0:exitcode=0:report_umrs=0:log_path=' + msan_log_path)

  # Increase maximum stack size to prevent tests from failing.
  limit = 128 * 1024 * 1024
  resource.setrlimit(resource.RLIMIT_STACK, (limit, limit))
  return env


def FindPackageDebs(package_name, work_directory):
  """Find package debs."""
  deb_paths = []
  cache = apt.Cache()

  for filename in os.listdir(work_directory):
    file_path = os.path.join(work_directory, filename)
    if not file_path.endswith('.deb'):
      continue

    # Matching package name.
    deb = debfile.DebPackage(file_path)
    if deb.pkgname == package_name:
      deb_paths.append(file_path)
      continue

    # Also include -dev packages that depend on the runtime package.
    pkg = cache[deb.pkgname]
    if pkg.section != 'libdevel' and pkg.section != 'universe/libdevel':
      continue

    # But ignore -dbg packages.
    if deb.pkgname.endswith('-dbg'):
      continue

    for dependency in deb.depends:
      if any(dep[0] == package_name for dep in dependency):
        deb_paths.append(file_path)
        break

  return deb_paths


def ExtractLibraries(deb_paths, work_directory, output_directory):
  """Extract libraries from .deb packages."""
  extract_directory = os.path.join(work_directory, 'extracted')
  if os.path.exists(extract_directory):
    shutil.rmtree(extract_directory, ignore_errors=True)

  os.mkdir(extract_directory)

  for deb_path in deb_paths:
    subprocess.check_call(['dpkg-deb', '-x', deb_path, extract_directory])

  extracted = []
  for root, _, filenames in os.walk(extract_directory):
    if 'libx32' in root or 'lib32' in root:
      continue

    for filename in filenames:
      if (not filename.endswith('.so') and '.so.' not in filename and
          not filename.endswith('.a') and '.a' not in filename):
        continue

      file_path = os.path.join(root, filename)
      rel_file_path = os.path.relpath(file_path, extract_directory)
      rel_directory = os.path.dirname(rel_file_path)

      target_dir = os.path.join(output_directory, rel_directory)
      if not os.path.exists(target_dir):
        os.makedirs(target_dir)

      target_file_path = os.path.join(output_directory, rel_file_path)
      extracted.append(target_file_path)
        
      if os.path.lexists(target_file_path):
        os.remove(target_file_path)

      if os.path.islink(file_path):
        link_path = os.readlink(file_path)
        if os.path.isabs(link_path):
          # Make absolute links relative.
          link_path = os.path.relpath(
              link_path, os.path.join('/', rel_directory))

        os.symlink(link_path, target_file_path)
      else:
        shutil.copy2(file_path, target_file_path)

  return extracted


def GetPackage(package_name):
  apt_cache = apt.Cache()
  version = apt_cache[package_name].candidate
  source_name = version.source_name
  local_source_name = source_name.replace('.', '_')

  custom_package_path = os.path.join(PACKAGES_DIR, local_source_name) + '.py'
  if not os.path.exists(custom_package_path):
    print('Using default package build steps.')
    return package.Package(source_name, version)

  print('Using custom package build steps.')
  module = imp.load_source('packages.' + local_source_name, custom_package_path)
  return module.Package(version)


def PatchRpath(path, output_directory):
  """Patch rpath to be relative to $ORIGIN."""
  try:
    rpaths = subprocess.check_output(
        ['patchelf', '--print-rpath', path]).strip()
  except subprocess.CalledProcessError:
    return

  if not rpaths:
    return

  processed_rpath = []
  rel_directory = os.path.join(
      '/', os.path.dirname(os.path.relpath(path, output_directory)))

  for rpath in rpaths.split(':'):
    if '$ORIGIN' in rpath:
      # Already relative.
      processed_rpath.append(rpath)
      continue

    processed_rpath.append(os.path.join(
        '$ORIGIN',
        os.path.relpath(rpath, rel_directory)))

  processed_rpath = ':'.join(processed_rpath)
  print('Patching rpath for', path, 'to', processed_rpath)
  subprocess.check_call(
      ['patchelf', '--force-rpath', '--set-rpath',
       processed_rpath, path])


def _CollectDependencies(apt_cache, pkg, cache, dependencies):
  """Collect dependencies that need to be built."""
  C_OR_CXX_DEPS = [
      'libc++1',
      'libc6',
      'libc++abi1',
      'libgcc1',
      'libstdc++6',
  ]

  BLACKLISTED_PACKAGES = [
      'libcapnp-0.5.3',  # fails to compile on newer clang.
      'libllvm5.0',
      'libmircore1',
      'libmircommon7',
      'libmirclient9',
      'libmirprotobuf3',
      'multiarch-support',
  ]

  if pkg.name in BLACKLISTED_PACKAGES:
    return False

  if pkg.section != 'libs' and pkg.section != 'universe/libs':
    return False

  if pkg.name in C_OR_CXX_DEPS:
    return True

  is_c_or_cxx = False
  for dependency in pkg.candidate.dependencies:
    dependency = dependency[0]

    if dependency.name in cache:
      is_c_or_cxx |= cache[dependency.name]
    else:
      is_c_or_cxx |= _CollectDependencies(apt_cache, apt_cache[dependency.name],
                                          cache, dependencies)
  if is_c_or_cxx:
    dependencies.append(pkg.name)

  cache[pkg.name] = is_c_or_cxx
  return is_c_or_cxx


def GetBuildList(package_name):
  """Get list of packages that need to be built including dependencies."""
  apt_cache = apt.Cache()
  pkg = apt_cache[package_name]

  dependencies = []
  _CollectDependencies(apt_cache, pkg, {}, dependencies)
  return dependencies


class MSanBuilder(object):
  """MSan builder."""

  def __init__(self, debug=False, log_path=None, work_dir=None, no_track_origins=False):
    self.debug = debug
    self.log_path = log_path
    self.work_dir = work_dir
    self.no_track_origins = no_track_origins
    self.env = None

  def __enter__(self):
    if not self.work_dir:
      self.work_dir = tempfile.mkdtemp(dir=self.work_dir)

    if os.path.exists(self.work_dir):
      shutil.rmtree(self.work_dir, ignore_errors=True)

    os.makedirs(self.work_dir)
    self.env = SetUpEnvironment(self.work_dir)

    if self.debug and self.log_path:
      self.env['WRAPPER_DEBUG_LOG_PATH'] = self.log_path

    if self.no_track_origins:
      self.env['MSAN_NO_TRACK_ORIGINS'] = '1'

    return self

  def __exit__(self, exc_type, exc_value, traceback):
    if not self.debug:
      shutil.rmtree(self.work_dir, ignore_errors=True)

  def Build(self, package_name, output_directory, create_subdirs=False):
    """Build the package and write results into the output directory."""
    deb_paths = FindPackageDebs(package_name, self.work_dir)
    if deb_paths:
      print('Source package already built for', package_name)
    else:
      pkg = GetPackage(package_name)

      pkg.InstallBuildDeps()
      source_directory = pkg.DownloadSource(self.work_dir)
      print('Source downloaded to', source_directory)

      # custom bin directory for custom build scripts to write wrappers.
      custom_bin_dir = os.path.join(self.work_dir, package_name + '_bin')
      os.mkdir(custom_bin_dir)
      env = self.env.copy()
      env['PATH'] = custom_bin_dir + ':' + env['PATH']

      pkg.Build(source_directory, env, custom_bin_dir)
      shutil.rmtree(custom_bin_dir, ignore_errors=True)

      deb_paths = FindPackageDebs(package_name, self.work_dir)

    if not deb_paths:
      raise MSanBuildException('Failed to find .deb packages.')

    print('Extracting', ' '.join(deb_paths))

    if create_subdirs:
      extract_directory = os.path.join(output_directory, package_name)
    else:
      extract_directory = output_directory

    extracted_paths = ExtractLibraries(deb_paths, self.work_dir,
                                       extract_directory)
    for extracted_path in extracted_paths:
      if not os.path.islink(extracted_path):
        PatchRpath(extracted_path, extract_directory)


def main():
  parser = argparse.ArgumentParser('msan_build.py', description='MSan builder.')
  parser.add_argument('package_names', nargs='+', help='Name of the packages.')
  parser.add_argument('output_dir', help='Output directory.')
  parser.add_argument('--create-subdirs', action='store_true',
                      help=('Create subdirectories in the output '
                            'directory for each package.'))
  parser.add_argument('--work-dir', help='Work directory.')
  parser.add_argument('--no-build-deps', action='store_true',
                      help='Don\'t build dependencies.')
  parser.add_argument('--debug', action='store_true', help='Enable debug mode.')
  parser.add_argument('--log-path', help='Log path for debugging.')
  parser.add_argument('--no-track-origins',
                      action='store_true',
                      help='Build with -fsanitize-memory-track-origins=0.')
  args = parser.parse_args()

  if args.no_track_origins:
    os.environ['MSAN_NO_TRACK_ORIGINS'] = '1'

  if not os.path.exists(args.output_dir):
    os.makedirs(args.output_dir)

  if args.no_build_deps:
    package_names = args.package_names
  else:
    all_packages = set()
    package_names = []

    # Get list of packages to build, including all dependencies.
    for package_name in args.package_names:
      for dep in GetBuildList(package_name):
        if dep in all_packages:
          continue

        if args.create_subdirs:
          os.mkdir(os.path.join(args.output_dir, dep))

        all_packages.add(dep)
        package_names.append(dep)

  print('Going to build:')
  for package_name in package_names:
    print('\t', package_name)

  with MSanBuilder(debug=args.debug, log_path=args.log_path,
                   work_dir=args.work_dir,
                   no_track_origins=args.no_track_origins) as builder:
    for package_name in package_names:
      builder.Build(package_name, args.output_dir, args.create_subdirs)


if __name__ == '__main__':
  main()
