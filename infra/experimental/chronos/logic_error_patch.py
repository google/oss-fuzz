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

from dataclasses import dataclass
import os
import pathlib
import random
import sys

import tree_sitter_cpp
from tree_sitter import Language, Parser, Query, QueryCursor

LANGUAGE = Language(tree_sitter_cpp.language())
PARSER = Parser(LANGUAGE)
EXCLUDE_DIRS = ['tests', 'test', 'examples'
                'example', 'build']
ROOT_PATH = os.path.abspath(pathlib.Path.cwd().resolve())
MAX_COUNT = 50


def _add_payload_random_functions(exts: list[str], payload: str) -> str:
  """Helper to attach payload to random functions found in any source."""
  count = 0

  # Walk and insert payload on the random line of random functions
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
          with open(path, 'r', encoding='utf-8') as f:
            source = f.read()
          if source:
            node = PARSER.parse(source.encode()).root_node
        except Exception:
          pass

        if not node:
          continue

        # Insert payload to random line in the function
        cursor = QueryCursor(Query(LANGUAGE, '( function_definition ) @funcs'))
        for func in cursor.captures(node).get('funcs', []):
          body = func.child_by_field_name('body')

          # Skip Class / Struct definition
          type_node = func.child_by_field_name('type')
          if not type_node or type_node.type not in [
              'primitive_type', 'type_identifier'
          ]:
            continue

          if body and body.text and random.choice([True, False]):
            func_source = body.text.decode()
            new_func_source = f'{{{payload} {func_source[1:]}'
            source = source.replace(func_source, new_func_source)
        try:
          with open(path, 'w', encoding='utf-8') as f:
            f.write(source)
          count += 1
        except Exception:
          pass


def normal_patch():
  """Do nothing and act as a control test that should always success."""
  return


def signal_abort_crash():
  """Insert abort call to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  _add_payload_random_functions(exts, 'abort();')


def builtin_trap_crash():
  """Insert builtin trap to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  _add_payload_random_functions(exts, '__builtin_trap();')


def null_write_crash():
  """Insert null pointer write to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  _add_payload_random_functions(exts, '*(volatile int*)0 = 0;')


def wrong_return_value():
  """modify random return statement to force an unit test failed in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp']
  primitives = {
      'bool', 'char', 'signed', 'unsigned', 'short', 'int', 'long', 'float',
      'double', 'wchar_t', 'char8_t', 'char16_t', 'char32_t', 'size_t'
  }
  count = 0

  # Walk and insert payload on the random line of random functions
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
          with open(path, 'r', encoding='utf-8') as f:
            source = f.read()
          if source:
            node = PARSER.parse(source.encode()).root_node
        except Exception:
          pass

        if not node:
          continue

        # Try simulate wrong return statement
        cursor = QueryCursor(Query(LANGUAGE, '( function_definition ) @funcs'))
        for func in cursor.captures(node).get('funcs', []):
          # Get return type
          rtn_node = func.child_by_field_name('type')
          if rtn_node and rtn_node.text:
            rtn = rtn_node.text.decode()
          else:
            rtn = None

          # Determine if return type is a pointer
          if func.child_by_field_name(
              'declarator').type == 'pointer_declarator':
            is_pointer = True
          else:
            is_pointer = False

          # If the return tyoe is a pointer or primitive types,
          #add return 0 at the beginning of the function
          body = func.child_by_field_name('body')
          if body and body.text and (is_pointer or rtn in primitives):
            func_source = body.text.decode()
            new_func_source = f'{{return 0; {func_source[1:]}'
            source = source.replace(func_source, new_func_source)

        try:
          with open(path, 'w', encoding='utf-8') as f:
            f.write(source)
          count += 1
        except Exception:
          pass


@dataclass
class LogicErrorPatch:
  """Dataclass to hold the patch function and expected result."""
  name: str
  func: callable
  expected_result: bool


LOGIC_ERROR_PATCHES: list[LogicErrorPatch] = [
    LogicErrorPatch(
        name='control_test',
        func=normal_patch,
        expected_result=True,
    ),
    LogicErrorPatch(
        name='sigabrt_crash',
        func=signal_abort_crash,
        expected_result=False,
    ),
    LogicErrorPatch(
        name='sigkill_crash',
        func=builtin_trap_crash,
        expected_result=False,
    ),
    LogicErrorPatch(
        name='sigsegv_crash',
        func=null_write_crash,
        expected_result=False,
    ),
    LogicErrorPatch(
        name='random_return_value',
        func=wrong_return_value,
        expected_result=False,
    )
]


def main():
  target = sys.argv[1]
  for logic_error_patch in LOGIC_ERROR_PATCHES:
    if logic_error_patch.name == target:
      logic_error_patch.func()


if __name__ == "__main__":
  main()
