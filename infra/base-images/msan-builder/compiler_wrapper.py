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
  M32_BIT_ARGS = [
      '-m32',
      '-mx32',
  ]

  return any(arg in M32_BIT_ARGS for arg in args)


def GetCompilerArgs(args):
  compiler_args = args[1:]

  if Is32Bit(args):
    # 32 bit builds not supported.
    compiler_args.extend([
        '-fno-sanitize=memory',
        '-fno-sanitize-memory-track-origins',
    ])

    return compiler_args

  # FORTIFY_SOURCE is not supported by sanitizers.
  compiler_args.extend([
      '-U_FORTIFY_SOURCE',
  ])

  REMOVED_ARGS = [
      '-g',
      '-Wl,-z,defs',
  ]

  args = [arg for arg in compiler_args if arg not in REMOVED_ARGS]
  args.append('-gline-tables-only')
  return args


def FindRealClang():
  return os.environ['REAL_CLANG_PATH']


def main(args):
  is_cxx = args[0].endswith('++')
  real_clang = FindRealClang()

  if is_cxx:
    real_clang += '++'

  args = [real_clang] + GetCompilerArgs(args)
  print(args, file=sys.stderr)
  sys.exit(subprocess.call(args))


if __name__ == '__main__':
  main(sys.argv)
