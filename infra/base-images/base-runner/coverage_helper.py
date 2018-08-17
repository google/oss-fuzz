#!/usr/bin/python3
# Copyright 2018 Google Inc.
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

import argparse
import os
import re
import subprocess
import sys


def get_shared_libraries(binary_paths):
  """Returns list of shared libraries used by specified binaries."""
  shared_libraries = []
  cmd = ['ldd']
  shared_library_path_re = re.compile(
      r'.*\.so[.0-9]*\s=>\s(.*' + os.getenv('OUT') + r'.*\.so[.0-9]*)\s.*')

  cmd.extend(binary_paths)
  output = subprocess.check_output(cmd).decode("utf-8", "ignore")

  for line in output.splitlines():
    match = shared_library_path_re.match(line)
    if not match:
      continue

    shared_library_path = match.group(1)
    if shared_library_path in shared_libraries:
      continue

    assert os.path.exists(shared_library_path), ('Shared library "%s" used by '
                                                 'the given target(s) does not '
                                                 'exist.' % shared_library_path)
    with open(shared_library_path, 'rb') as f:
      data = f.read()

    # Do not add non-instrumented libraries. Otherwise, llvm-cov errors outs.
    if b'__llvm_cov' in data:
      shared_libraries.append(shared_library_path)

  return shared_libraries


def print_shared_libraries(args):
  if not args.object:
    print("ERROR: No binaries are specified.", file=sys.stderr)
    return 1

  paths = get_shared_libraries(args.object)
  if not paths:
    return 0

  # Print output in the format that can be passed to llvm-cov tool.
  output = ' '.join(['-object=%s' % path for path in paths])
  print(output)
  return 0


def main():
  parser = argparse.ArgumentParser('coverage_helper',
                                   description='coverage script helper')
  subparsers = parser.add_subparsers(dest='command')

  shared_libs_parser = subparsers.add_parser('shared_libs',
                                             help='Detect shared libraries.')
  shared_libs_parser.add_argument('-object', action='append',
                                  help='Path to the binary using shared libs.')

  args = parser.parse_args()
  if args.command == 'shared_libs':
    return print_shared_libraries(args)


if __name__ == '__main__':
  sys.exit(main())
