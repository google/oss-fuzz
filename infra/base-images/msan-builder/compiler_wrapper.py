#!/usr/bin/env python
# Compiler wrapper

import os
import sys
import subprocess


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
      '-Wl,-z,defs',
  ]

  return [arg for arg in compiler_args if arg not in REMOVED_ARGS]


def FindRealClang():
  return os.path.join(os.environ['REAL_CLANG_PATH'])


def main(args):
  is_cxx = args[0].endswith('++')
  real_clang = FindRealClang()

  if is_cxx:
    real_clang += '++'

  args = [real_clang] + GetCompilerArgs(args)
  print args
  sys.exit(subprocess.call(args))


if __name__ == '__main__':
  main(sys.argv)
