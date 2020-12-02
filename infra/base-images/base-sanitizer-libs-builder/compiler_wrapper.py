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
"""Wrapper script to call clang or GCC with modified arguments."""
from __future__ import print_function
import os
import subprocess
import sys

import msan_build

GCC_ONLY_ARGS = [
    '-aux-info',
]

M32_BIT_ARGS = [
    '-m32',
    '-mx32',
]


def invoked_as_gcc():
  """Return whether or not we're pretending to be GCC."""
  return sys.argv[0].endswith('gcc') or sys.argv[0].endswith('g++')


def is_32_bit(args):
  """Return whether or not we're 32-bit."""
  return any(arg in M32_BIT_ARGS for arg in args)


def filter_wl_arg(arg):
  """Remove -z,defs and equivalents from a single -Wl option."""
  parts = arg.split(',')[1:]

  filtered = []
  for part in parts:
    if part == 'defs':
      removed = filtered.pop()
      assert removed == '-z'
      continue

    if part == '--no-undefined':
      continue

    filtered.append(part)

  if filtered:
    return '-Wl,' + ','.join(filtered)

  # Filtered entire argument.
  return None


def _remove_last_matching(args, find):
  for i in range(len(args) - 1, -1, -1):
    if args[i] == find:
      del args[i]
      return

  raise IndexError('Not found')


def remove_z_defs(args):
  """Remove unsupported -Wl,-z,defs linker option."""
  filtered = []

  for arg in args:
    if arg == '-Wl,defs':
      _remove_last_matching(filtered, '-Wl,-z')
      continue

    if arg == '-Wl,--no-undefined':
      continue

    if arg.startswith('-Wl,'):
      arg = filter_wl_arg(arg)
      if not arg:
        continue

    filtered.append(arg)

  return filtered


def get_compiler_args(args, is_cxx):
  """Generate compiler args."""
  compiler_args = args[1:]

  if is_32_bit(args):
    # 32 bit builds not supported.
    compiler_args.extend([
        '-fno-sanitize=memory',
        '-fno-sanitize-memory-track-origins',
    ])

    return compiler_args

  compiler_args = remove_z_defs(compiler_args)
  compiler_args.extend([
      # FORTIFY_SOURCE is not supported by sanitizers.
      '-U_FORTIFY_SOURCE',
      '-Wp,-U_FORTIFY_SOURCE',
      # Reduce binary size.
      '-gline-tables-only',
      # Disable all warnings.
      '-w',
      # LTO isn't supported.
      '-fno-lto',
  ])

  if invoked_as_gcc():
    compiler_args.extend([
        # For better compatibility with flags passed via -Wa,...
        '-fno-integrated-as',
    ])

  if '-fsanitize=memory' not in args:
    # If MSan flags weren't added for some reason, add them here.
    compiler_args.extend(msan_build.get_injected_flags())

  if is_cxx:
    compiler_args.append('-stdlib=libc++')

  return compiler_args


def find_real_clang():
  """Return path to real clang."""
  return os.environ['REAL_CLANG_PATH']


def fallback_to_gcc(args):
  """Check whether if we should fall back to GCC."""
  if not invoked_as_gcc():
    return False

  return any(arg in GCC_ONLY_ARGS for arg in args[1:])


def main(args):
  """Modify arguments and call the real compiler."""
  if fallback_to_gcc(args):
    sys.exit(
        subprocess.call(['/usr/bin/' + os.path.basename(args[0])] + args[1:]))

  is_cxx = args[0].endswith('++')
  real_clang = find_real_clang()

  if is_cxx:
    real_clang += '++'

  args = [real_clang] + get_compiler_args(args, is_cxx)
  debug_log_path = os.getenv('WRAPPER_DEBUG_LOG_PATH')
  if debug_log_path:
    with open(debug_log_path, 'a') as log_file:
      log_file.write(str(args) + '\n')

  sys.exit(subprocess.call(args))


if __name__ == '__main__':
  main(sys.argv)
