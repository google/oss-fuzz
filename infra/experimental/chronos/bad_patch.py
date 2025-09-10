# Copyright 2025 Google LLC
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
"""Helper to generate bad patches for replay test using different approach."""

import os
import pathlib
import random
import sys

import tree_sitter_cpp
from tree_sitter import Language, Node, Parser, Query, QueryCursor

LANGUAGE = Language(tree_sitter_cpp.language())
PARSER = Parser(LANGUAGE)
EXCLUDE_DIRS = ['tests', 'test', 'example', 'build']
ROOT_PATH = os.path.abspath(pathlib.Path.cwd().resolve())
MAX_COUNT = 50


def normal_compile():
  """Do nothing and act as a control test that should always success."""
  pass


def source_code_compile_error():
  """Insert garbage code to all found source files in the /src/ directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  payload = 'GARBAGE GARBAGE'

  # Walk and insert garbage code
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      if any(file.endswith(ext) for ext in exts):
        path = os.path.join(cur, file)
        try:
          with open(path, 'a') as f:
            f.write(payload)
        except Exception:
          pass


def macro_compile_error():
  """Insert explicit macro error to all found header files in the /src/ directory."""
  exts = ['.h', '.hpp']
  payload = '#error THIS_SHOULD_BE_FAILING'

  # Walk and insert error macro
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      if any(file.endswith(ext) for ext in exts):
        path = os.path.join(cur, file)
        try:
          with open(path, 'a') as f:
            f.write(payload)
        except Exception:
          pass


def missing_header_error():
  """Insert wrong header inclusion to all found source files in the /src/ directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx']
  payload = '#include header_not_exist.h\n'
  count = 0

  # Walk and insert missing header inclusion
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      # Only modify a handful of files
      if count > MAX_COUNT:
        return

      # Skip random file
      if random.choice([True, False]):
        continue

      if any(file.endswith(ext) for ext in exts):
        path = os.path.join(cur, file)
        try:
          # Read source file
          source = ''
          with open(path, 'r') as f:
            source = f.read()
          if not source:
            continue

          # Append a wrong header inclusion at the beginning
          with open(path, 'w') as f:
            f.write(payload)
            f.write(source)
          count += 1
        except Exception:
          pass


def duplicate_symbol_error():
  """Insert duplicate symbol to all found source files in the /src/ directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx']
  count = 0

  # Walk and insert missing header inclusion
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      # Only modify a handful of files
      if count > MAX_COUNT:
        return

      if any(file.endswith(ext) for ext in exts):
        path = os.path.join(cur, file)
        node = None
        new_source = None
        try:
          # Try read and parse the source with tree-sitter
          source = ''
          with open(path, 'r') as f:
            source = f.read()
          if source:
            node = PARSER.parse(source.encode()).root_node
        except:
          pass

        if not node:
          continue

        # Found random declaration and duplicate it
        cursor = QueryCursor(Query(LANGUAGE, '( declaration ) @decl'))
        for declaration in cursor.captures(node).get('decl', []):
          if declaration.text:
            target = declaration.text.decode()
            new_source = source.replace(target, target + target)
            break

        # Add source code with duplicated declaration randomly
        if new_source and random.choice([True, False]):
          try:
            with open(path, 'w') as f:
              f.write(new_source)
            count += 1
          except:
            pass


BAD_PATCH_GENERATOR = {
    'control_test': {
        'func': normal_compile,
        'rc': [0],
    },
    'compile_error': {
        'func': source_code_compile_error,
        'rc': [1, 2],
    },
    'macro_error': {
        'func': macro_compile_error,
        'rc': [1, 2],
    },
    'missing_headers': {
        'func': missing_header_error,
        'rc': [1, 2],
    },
    'duplicate_symbols': {
        'func': duplicate_symbol_error,
        'rc': [1, 2],
    },
}


def main():
  target = sys.argv[1]
  BAD_PATCH_GENERATOR[target]['func']()


if __name__ == "__main__":
  main()
