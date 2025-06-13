#!/usr/bin/env python
import os
import shutil
import stat

_REAL_SUFFIX = '.real'
_WRAPPER_TEMPLATE = """#!/usr/bin/env python3

import sys
import os

def main():
  target = sys.argv[0] + '.real'
{contents}
  os.execv(target, sys.argv)


if __name__ == '__main__':
  main()
"""


def create_wrapper(contents: str):
  return _WRAPPER_TEMPLATE.format(contents=contents)


def main():
  dummy_script_content = '#!/bin/sh'
  dummy_scripts = [
      '/usr/bin/autoconf',
      '/usr/bin/autoheader',
      '/usr/bin/autom4te',
      '/usr/bin/automake',
      '/usr/bin/autopoint',
      '/usr/bin/autoreconf',
      '/usr/bin/autoscan',
      '/usr/bin/autoupdate',
  ]

  for script_path in dummy_scripts:
    with open(script_path, 'w') as f:
      f.write(dummy_script_content)
    os.chmod(script_path, 0o755)

  files_to_move = (
      '/usr/bin/cmake',
      '/usr/local/bin/cmake',
      '/bin/sh',
      '/bin/bash',
      '/usr/bin/ln',
      '/usr/bin/make',
      '/usr/bin/meson',
      '/usr/bin/mkdir',
      '/usr/bin/zip',
  )

  for src in files_to_move:
    if os.path.exists(src):
      shutil.move(src, src + _REAL_SUFFIX)

  # Create a shell wrapper that stubs out `configure` and `autogen`.
  with open('/bin/sh', 'w') as f:
    f.write(
        create_wrapper("""
  if any(os.path.basename(arg) in ('configure', 'autogen.sh') for arg in sys.argv[1:]):
    sys.exit(0)
"""))

  shutil.copyfile('/bin/sh', '/bin/bash')

  # Stub out `make clean`.
  with open('/usr/bin/make', 'w') as f:
    f.write(
        create_wrapper("""
  if any(arg == 'clean' for arg in sys.argv[1:]):
    sys.exit(0)
"""))

  # Stub out `meson setup`.
  with open('/usr/bin/meson', 'w') as f:
    f.write(
        create_wrapper("""
  if any(arg == 'setup' for arg in sys.argv[1:]):
    sys.exit(0)
"""))

  shutil.copyfile('/bin/sh', '/bin/bash')

  # Stub out cmake, but allow cmake --build.
  with open('/usr/bin/cmake', 'w') as f:
    f.write(
        create_wrapper("""
  if not any(arg == '--build' for arg in sys.argv[1:]):
    sys.exit(0)
"""))
  shutil.copyfile('/usr/bin/cmake', '/usr/local/bin/cmake')

  # Add -p to mkdir calls to allow it to be run twice.
  with open('/usr/bin/mkdir', 'w') as f:
    f.write(
        create_wrapper("""
  if not any(arg == '-p' for arg in sys.argv[1:]):
    sys.argv.insert(1, '-p')
"""))

  # Don't zip something that already exists.
  with open('/usr/bin/zip', 'w') as f:
    f.write(
        create_wrapper("""
  if (any(arg.endswith('.zip') and os.path.exists(arg) for arg in sys.argv[1:])):
    sys.exit(0)
"""))

  # Add -f to ln.
  with open('/usr/bin/ln', 'w') as f:
    f.write(
        create_wrapper("""
  if not any(arg == '-f' for arg in sys.argv[1:]):
    sys.argv.insert(1, '-f')
"""))

  for file_path in files_to_move:
    if os.path.exists(file_path):
      os.chmod(file_path, 0o755)


if __name__ == '__main__':
  main()
