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
import subprocess
import sys

try:
  import tree_sitter_cpp
  from tree_sitter import Language, Parser, Query, QueryCursor
except (ModuleNotFoundError, ImportError):
  # pass. Allow this module to be imported even when tree-sitter
  # is not available.
  pass

EXCLUDE_DIRS = ['tests', 'test', 'examples', 'example', 'build']
ROOT_PATH = os.path.abspath(pathlib.Path.cwd().resolve())
MAX_FILES_TO_PATCH = 50


def _add_payload_random_functions(exts: list[str], payload: str) -> str:
  """Helper to attach payload to random functions found in any source."""
  count = 0

  treesitter_parser = Parser(Language(tree_sitter_cpp.language()))
  # Walk and insert payload on the random line of random functions
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      # Only change some files randomly
      if count > MAX_FILES_TO_PATCH:
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
            node = treesitter_parser.parse(source.encode()).root_node
        except Exception:
          pass

        if not node:
          continue

        # Insert payload to random line in the function
        cursor = QueryCursor(
            Query(Language(tree_sitter_cpp.language()),
                  '( function_definition ) @funcs'))
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
            # new_func_source = f'{{ {payload} {func_source[1:]}'
            if len(func_source) > 10:
              new_func_source = f'{{ {payload} {func_source[1:]}'
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
  exts = ['.c', '.cc', '.cpp', '.cxx']
  _add_payload_random_functions(exts, 'abort();')


def builtin_trap_crash():
  """Insert builtin trap to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx']
  _add_payload_random_functions(exts, '__builtin_trap();')


def null_write_crash():
  """Insert null pointer write to force a crash in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx']
  _add_payload_random_functions(exts, '*(volatile int*)0 = 0;')


def wrong_return_value():
  """modify random return statement to force an unit test failed in source files found in the /src/directory."""
  exts = ['.c', '.cc', '.cpp', '.cxx']
  primitives = {
      'bool', 'char', 'signed', 'unsigned', 'short', 'int', 'long', 'float',
      'double', 'wchar_t', 'char8_t', 'char16_t', 'char32_t', 'size_t'
  }
  count = 0
  treesitter_parser = Parser(Language(tree_sitter_cpp.language()))
  # Walk and insert payload on the random line of random functions
  for cur, dirs, files in os.walk(ROOT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      # Only change some files randomly
      if count > MAX_FILES_TO_PATCH:
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
            node = treesitter_parser.parse(source.encode()).root_node
        except Exception:
          pass

        if not node:
          continue

        # Try simulate wrong return statement
        cursor = QueryCursor(
            Query(Language(tree_sitter_cpp.language()),
                  '( function_definition ) @funcs'))
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
            new_func_source = f'{{  {func_source[1:]}'
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
        name='sigkill_crash',
        func=builtin_trap_crash,
        expected_result=False,
    ),
    LogicErrorPatch(
        name='sigabrt_crash',
        func=signal_abort_crash,
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


def _capture_source_control():
  """Capture the source directory where source control is located."""

  # List all directories under /src/
  oss_fuzz_dirs = [
      'aflplusplus', 'fuzztest', 'honggfuzz', 'libfuzzer', 'googletest'
  ]
  project_dirs = []
  for dir_name in os.listdir('/src/'):
    if dir_name in oss_fuzz_dirs:
      continue
    if os.path.isdir(os.path.join('/src/', dir_name)):
      project_dirs.append(dir_name)

  # If there is only a single new project directory, then we are
  # almost certain this is the right directory.
  if len(project_dirs) == 1:
    # Check if there is a .git directory
    if os.path.isdir(os.path.join('/src/', project_dirs[0], '.git')):
      return ('git', os.path.join('/src/', project_dirs[0]))
    elif os.path.isdir(os.path.join('/src/', project_dirs[0], '.svn')):
      return ('svn', os.path.join('/src/', project_dirs[0]))
  else:
    print('Wrong number of directories found under /src/')
    print(project_dirs)

  if len(project_dirs) > 1:
    print('Multiple project directories found under /src/')
    # If we have a project name, try to use this
    project_name = os.getenv('PROJECT_NAME', 'unknown_project')
    if project_name in project_dirs:
      if os.path.isdir(os.path.join('/src/', project_name, '.git')):
        return ('git', os.path.join('/src/', project_name))
      elif os.path.isdir(os.path.join('/src/', project_name, '.svn')):
        return ('svn', os.path.join('/src/', project_name))
  return None, None


def diff_patch_analysis(stage: str) -> int:
  """Check if run_tests.sh generates patches that affect
  source control versioning.
  
  
  Returns:   int: 0 if no patch found, 1 if patch found and -1 on
            unkonwn (such as due to unsupported version control).
  """

  print(
      f'Diff patch analysis begin. Stage: {stage}, Current working dir: {os.getcwd()}'
  )
  if stage == 'before':
    print('Diff patch analysis before stage.')
    type, project_dir = _capture_source_control()
    if not type:
      print('Uknown version control system.')
      return -1

    print('%s repo found: %s' % (type, project_dir))
    try:
      subprocess.check_call('cd %s && %s diff ./ >> /tmp/chronos-before.diff' %
                            (project_dir, type),
                            shell=True)
    except subprocess.CalledProcessError:
      pass
    return 0

  elif stage == 'after':
    print('Diff patch analysis after stage.')
    type, project_dir = _capture_source_control()
    if not type:
      print('Uknown version control system.')
      return -1

    print('%s repo found: %s' % (type, project_dir))
    subprocess.check_call('cd %s && %s diff ./ >> /tmp/chronos-after.diff' %
                          (project_dir, type),
                          shell=True)

    try:
      subprocess.check_call(
          'diff /tmp/chronos-before.diff /tmp/chronos-after.diff > /tmp/chronos-diff.patch',
          shell=True)
    except subprocess.CalledProcessError:
      pass
    print('Diff patch generated at /tmp/chronos-diff.patch')
    print('Difference between diffs:')
    with open('/tmp/chronos-diff.patch', 'r', encoding='utf-8') as f:
      diff_content = f.read()
    if diff_content.strip():
      patch_found = True
      print(diff_content)
    else:
      patch_found = False

    if patch_found:
      print(
          'Patch result: failed. Patch found that affects source control versioning.'
      )
      return 1
    else:
      print(
          'Patch result: success. No patch found that affects source control versioning.'
      )
      return 0

  else:
    print(
        f'Patch result: failed. Unknown stage {stage} for diff patch analysis.')
    return -1


def main():
  """Main entrypoint."""

  project_name = os.getenv('PROJECT_NAME', 'unknown_project')
  print(f'Integrity validator run tests for project: {project_name}')
  command = sys.argv[1]
  if command == 'semantic-patch':
    target_patch = sys.argv[2]
    for logic_error_patch in LOGIC_ERROR_PATCHES:
      if logic_error_patch.name == target_patch:
        logic_error_patch.func()
  elif command == 'diff-patch':
    print(f'Diff patching for stage %s.' % sys.argv[2])
    result = diff_patch_analysis(sys.argv[2])
    sys.exit(result)


if __name__ == "__main__":
  main()
