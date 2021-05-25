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
import re
import shutil
import subprocess
import sys

INSTRUMENTED_LIBRARIES_DIRNAME = 'instrumented_libraries'
MSAN_LIBS_PATH = os.getenv('MSAN_LIBS_PATH', '/msan')


def IsElf(file_path):
  """Whether if the file is an elf file."""
  with open(file_path) as f:
    return f.read(4) == '\x7fELF'


def Ldd(binary_path):
  """Run ldd on a file."""
  try:
    output = subprocess.check_output(['ldd', binary_path],
                                     stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError:
    print('Failed to call ldd on', binary_path, file=sys.stderr)
    return []

  libs = []

  OUTPUT_PATTERN = re.compile(r'\s*([^\s]+)\s*=>\s*([^\s]+)')
  for line in output.splitlines():
    match = OUTPUT_PATTERN.match(line)
    if not match:
      continue

    libs.append((match.group(1), match.group(2)))

  return libs


def FindLib(path):
  """Find instrumented version of lib."""
  candidate_path = os.path.join(MSAN_LIBS_PATH, path[1:])
  if os.path.exists(candidate_path):
    return candidate_path

  for lib_dir in os.listdir(MSAN_LIBS_PATH):
    candidate_path = os.path.join(MSAN_LIBS_PATH, lib_dir, path[1:])
    if os.path.exists(candidate_path):
      return candidate_path

  return None


def PatchBinary(binary_path, instrumented_dir):
  """Patch binary to link to instrumented libs."""
  extra_rpaths = set()

  for name, path in Ldd(binary_path):
    if not os.path.isabs(path):
      continue

    instrumented_path = FindLib(path)
    if not instrumented_path:
      print('WARNING: Instrumented library not found for',
            path,
            file=sys.stderr)
      continue

    target_path = os.path.join(instrumented_dir, path[1:])
    if not os.path.exists(target_path):
      print('Copying instrumented lib to', target_path)
      target_dir = os.path.dirname(target_path)
      if not os.path.exists(target_dir):
        os.makedirs(target_dir)
      shutil.copy2(instrumented_path, target_path)

    extra_rpaths.add(
        os.path.join('$ORIGIN', INSTRUMENTED_LIBRARIES_DIRNAME,
                     os.path.dirname(path[1:])))

  if not extra_rpaths:
    return

  existing_rpaths = subprocess.check_output(
      ['patchelf', '--print-rpath', binary_path]).strip()
  processed_rpaths = ':'.join(extra_rpaths)
  if existing_rpaths:
    processed_rpaths += ':' + existing_rpaths
  print('Patching rpath for', binary_path, 'from', existing_rpaths, 'to',
        processed_rpaths)

  subprocess.check_call([
      'patchelf', '--force-rpath', '--set-rpath', processed_rpaths, binary_path
  ])


def PatchBuild(output_directory):
  """Patch build to use msan libs."""
  instrumented_dir = os.path.join(output_directory,
                                  INSTRUMENTED_LIBRARIES_DIRNAME)
  if not os.path.exists(instrumented_dir):
    os.mkdir(instrumented_dir)

  for root_dir, _, filenames in os.walk(output_directory):
    for filename in filenames:
      if filename == "llvm-symbolizer":
        continue

      file_path = os.path.join(root_dir, filename)

      if os.path.islink(file_path):
        continue

      if not IsElf(file_path):
        continue

      PatchBinary(file_path, instrumented_dir)


def main():
  parser = argparse.ArgumentParser('patch_build.py',
                                   description='MSan build patcher.')
  parser.add_argument('output_dir', help='Output directory.')

  args = parser.parse_args()

  PatchBuild(os.path.abspath(args.output_dir))


if __name__ == '__main__':
  main()
