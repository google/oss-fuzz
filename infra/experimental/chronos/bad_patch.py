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

def normal_compile() -> tuple[str, int]:
  """Generate empty command and act as a control test that should always success."""
  return '', 0

def source_code_compile_error() -> tuple[str, int]:
  """Generate shell commands to insert garbage code to all found source files
  in the /src/ directory."""

  return (r'find . \( -type d \( -name build -o -name test -o -name tests \) -prune \) -o '
          r'''-type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) '''
          r'''-exec tee -a {} <<< \"GARBAGE GARBAGE\" \;'''), 2

BAD_PATCH_GENERATOR = {
  'control_test': normal_compile,
  'compile_error': source_code_compile_error,
}
