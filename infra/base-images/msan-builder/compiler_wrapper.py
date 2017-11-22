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


def Is32Bit(args):
  """Return whether or not we're 32-bit."""
  M32_BIT_ARGS = [
      '-m32',
      '-mx32',
  ]

  return any(arg in M32_BIT_ARGS for arg in args)


def RemoveZDefs(args):
  """Remove unsupported -Wl,-z,defs linker option."""
  filtered = []

  for arg in args:
    if arg == '-Wl,-z,defs':
      continue

    if arg == '-Wl,defs':
      # Remove previous -Wl,-z
      filtered.pop()
      continue

    filtered.append(arg)

  return filtered


def GetCompilerArgs(args):
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
      # Reduce binary size.
      '-gline-tables-only',
      # Disable all warnings.
      '-w',
  ])

  return compiler_args


def FindRealClang():
  """Return path to real clang."""
  return os.environ['REAL_CLANG_PATH']


def main(args):
  is_cxx = args[0].endswith('++')
  real_clang = FindRealClang()

  if is_cxx:
    real_clang += '++'

  args = [real_clang] + GetCompilerArgs(args)
  debug_log_path = os.getenv('WRAPPER_DEBUG_LOG_PATH')
  if debug_log_path:
    with open(debug_log_path, 'a') as f:
      f.write(str(args) + '\n')

  sys.exit(subprocess.call(args))


if __name__ == '__main__':
  main(sys.argv)
