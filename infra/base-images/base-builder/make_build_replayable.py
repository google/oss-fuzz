#!/usr/bin/env python3
# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/env python
import os
import shutil

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
      # Applying patches is not idempotent.
      '/usr/bin/patch',
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
      '/usr/bin/git',
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

  # Stub out cmake, but allow cmake --build, --install, -E (command mode), -P
  # (script mode).
  with open('/usr/bin/cmake', 'w') as f:
    f.write(
        create_wrapper("""
  if not any(arg in ('--build', '--install', '-E', '-P', '--version') for arg in sys.argv[1:]):
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

  # Don't allow git `reset` or `clean` or `apply`.
  # reset/clean might remove build artifacts.
  # clone is not idempotent.
  # applying patches is not idempotent.
  with open('/usr/bin/git', 'w') as f:
    f.write(
        create_wrapper("""
  if any(arg in ('clean', 'clone', 'reset', 'apply', 'submodule') for arg in sys.argv[1:]):
    sys.exit(0)
"""))

  for file_path in files_to_move:
    if os.path.exists(file_path):
      os.chmod(file_path, 0o755)


if __name__ == '__main__':
  main()
