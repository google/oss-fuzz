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
import os
import subprocess
import sys

import msan_build

GCC_ONLY_ARGS = [
    '-aux-info',
]


def InvokedAsGcc():
  """Return whether or not we're pretending to be GCC."""
  return sys.argv[0].endswith('gcc') or sys.argv[0].endswith('g++')


def Is32Bit(args):
  """Return whether or not we're 32-bit."""
  M32_BIT_ARGS = [
      '-m32',
      '-mx32',
  ]

  return any(arg in M32_BIT_ARGS for arg in args)


def FilterWlArg(arg):
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


def _RemoveLastMatching(l, find):
  for i in xrange(len(l) - 1, -1, -1):
    if l[i] == find:
      del l[i]
      return

  raise IndexError('Not found')


def RemoveZDefs(args):
  """Remove unsupported -Wl,-z,defs linker option."""
  filtered = []

  for arg in args:
    if arg == '-Wl,defs':
      _RemoveLastMatching(filtered, '-Wl,-z')
      continue

    if arg == '-Wl,--no-undefined':
      continue

    if arg.startswith('-Wl,'):
      arg = FilterWlArg(arg)
      if not arg:
        continue

    filtered.append(arg)

  return filtered


def GetCompilerArgs(args, is_cxx):
  """Generate compiler args."""
  compiler_args = args[1:]

  if Is32Bit(args):
    # 32 bit builds not supported.
    compiler_args.extend([
        '-fno-sanitize=memory',
        '-fno-sanitize-memory-track-origins',
    ])

    return compiler_args

  compiler_args = RemoveZDefs(compiler_args)
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

  if InvokedAsGcc():
    compiler_args.extend([
      # For better compatibility with flags passed via -Wa,...
      '-fno-integrated-as',
    ])

  if '-fsanitize=memory' not in args:
    # If MSan flags weren't added for some reason, add them here.
    compiler_args.extend(msan_build.GetInjectedFlags())

  if is_cxx:
    compiler_args.append('-stdlib=libc++')

  return compiler_args


def FindRealClang():
  """Return path to real clang."""
  return os.environ['REAL_CLANG_PATH']


def FallbackToGcc(args):
  """Check whether if we should fall back to GCC."""
  if not InvokedAsGcc():
    return False

  return any(arg in GCC_ONLY_ARGS for arg in args[1:])


def main(args):
  if FallbackToGcc(args):
    sys.exit(subprocess.call(['/usr/bin/' + os.path.basename(args[0])] +
                             args[1:]))

  is_cxx = args[0].endswith('++')
  real_clang = FindRealClang()

  if is_cxx:
    real_clang += '++'

  args = [real_clang] + GetCompilerArgs(args, is_cxx)
  debug_log_path = os.getenv('WRAPPER_DEBUG_LOG_PATH')
  if debug_log_path:
    with open(debug_log_path, 'a') as f:
      f.write(str(args) + '\n')

  sys.exit(subprocess.call(args))


if __name__ == '__main__':
  main(sys.argv)
