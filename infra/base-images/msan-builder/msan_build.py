#!/usr/bin/env python

import os
import shutil
import sys
import subprocess
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


class MSanBuildException(Exception):
  """Base exception."""


def SetUpEnvironment(work_dir):
  env = {}
  env['REAL_CLANG_PATH'] = subprocess.check_output(['which', 'clang']).strip()
  print 'Real clang at', env['REAL_CLANG_PATH']
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

  env['DEB_BUILD_OPTIONS'] = 'nocheck'
  env['DEB_CFLAGS_APPEND'] = (
      '-fsanitize=memory -fsanitize-memory-track-origins=2')
  env['DEB_CXXFLAGS_APPEND'] = (
      '-fsanitize=memory -fsanitize-memory-track-origins=2')
  env['DEB_LDFLAGS_APPEND'] = (
      '-fsanitize=memory -fsanitize-memory-track-origins=2')
  env['DPKG_GENSYMBOLS_CHECK_LEVEL'] = '0'

  env['PATH'] = bin_dir + ':' + os.environ['PATH']

  return env


def InstallBuildDeps(package_name):
  subprocess.check_call(['apt-get', 'build-dep', '-y', package_name])


def DownloadPackageSource(package_name, download_directory):
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
  return [subdir for subdir in os.listdir(directory)
          if os.path.isdir(os.path.join(directory, subdir))]


def BuildDebianPackage(source_directory, env):
  subprocess.check_call(
      ['dpkg-buildpackage', '-us', '-uc', '-b'], cwd=source_directory, env=env)


def ExtractDebianPackages(source_directory, output_directory):
  for filename in os.listdir(source_directory):
    file_path = os.path.join(source_directory, filename)
    if not file_path.endswith('.deb'):
      continue

    subprocess.check_call(['dpkg-deb', '-x', file_path, output_directory])


class MSanBuilder(object):
  """MSan builder."""

  def __enter__(self):
    self.work_dir = tempfile.mkdtemp()
    self.env = SetUpEnvironment(self.work_dir)
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    shutil.rmtree(self.work_dir, ignore_errors=True)

  def build(self, package_name, output_directory):
    InstallBuildDeps(package_name)
    source_directory = DownloadPackageSource(package_name, self.work_dir)
    print 'Source downloaded to', source_directory

    BuildDebianPackage(source_directory, self.env)
    ExtractDebianPackages(self.work_dir, output_directory)


def main(args):
  if len(args) < 3:
    print 'Usage:', args[0], 'package_name', 'output_dir'
    sys.exit(1)

  package_name = args[1]
  output_dir = args[2]
  with MSanBuilder() as builder:
    builder.build(package_name, output_dir)


if __name__ == '__main__':
  main(sys.argv)



