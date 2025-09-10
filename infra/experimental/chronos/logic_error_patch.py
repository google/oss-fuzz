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
"""Helper to generate logic error patches for general test using different approach."""

import os
import pathlib
import random
import sys

import tree_sitter_cpp
from tree_sitter import Language, Node, Parser, Query, QueryCursor

LANGUAGE = Language(tree_sitter_cpp.language())
PARSER = Parser(LANGUAGE)
EXCLUDE_DIRS = ['tests', 'test', 'examples' 'example', 'build']
ROOT_PATH = os.path.abspath(pathlib.Path.cwd().resolve())
MAX_COUNT = 50

def normal_patch():
  """Do nothing and act as a control test that should always success."""
  pass


def signal_abort_crash():
  """Insert abort call to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  count = 0

  # Walk and insert abort() function call
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      # Only change some files randomly
      if count > MAX_COUNT:
        return

      if any(file.endswith(ext) for ext in exts):
        path = os.path.join(cur, file)
        node = None
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
        cursor = QueryCursor(Query(LANGUAGE, '( function_definition ) @funcs'))
        for func in cursor.captures(node).get('funcs', []):
          body = func.child_by_field_name('body')
          if body and body.text and random.choice([True, False]):
            func_source = body.text.decode()
            new_func_source = f'{{abort(); {func_source[1:]}'
            source = source.replace(func_source, new_func_source)

        if random.choice([True, False]):
          try:
            with open(path, 'w') as f:
              f.write(source)
            count += 1
          except:
            pass


LOGIC_ERROR_PATCH_GENERATOR = {
  'control_test': {
    'func': normal_patch,
    'result': True,
  },
  'sigabrt_crash': {
    'func': signal_abort_crash,
    'result': False,
  },
}


def main():
  target = sys.argv[1]
  LOGIC_ERROR_PATCH_GENERATOR[target]['func']()


if __name__ == "__main__":
  main()
