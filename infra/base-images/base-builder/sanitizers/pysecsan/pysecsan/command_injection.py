# Copyright 2022 Google LLC
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
"""Sanitizers for capturing code injections."""

from typing import Optional
from pysecsan import sanlib


def get_all_substr_prefixes(main_str, sub_str):
  """Yields all strings prefixed with sub_str in main_str."""
  idx = 0
  while True:
    idx = main_str.find(sub_str, idx)
    if idx == -1:
      return
    yield main_str[0:idx]
    # Increase idx the length of the substring from the current position
    # where an occurence of the substring was found.
    idx += len(sub_str)


def check_code_injection_match(elem, check_unquoted=False) -> Optional[str]:
  """identify if elem is an injection match."""
  # Check exact match
  if elem == 'exec-sanitizer':
    return 'Explicit command injection found.'

  # Check potential for injecting into a string
  if 'FROMFUZZ' in elem:
    if check_unquoted:
      # return true if any index is unquoted
      for sub_str in get_all_substr_prefixes(elem, 'FROMFUZZ'):
        if sub_str.count('\"') % 2 == 0:
          return 'Fuzzer controlled content in data. Code injection potential.'

      # Return None if all fuzzer taints were quoted
      return None
    return 'Fuzzer-controlled data in command string. Injection potential.'
  return None


# pylint: disable=invalid-name
def hook_pre_exec_subprocess_Popen(cmd, **kwargs):
  """Hook for subprocess.Popen."""

  arg_shell = 'shell' in kwargs and kwargs['shell']

  # Command injections depend on whether the first argument is a list of
  # strings or a string. Handle this now.
  # Example: tests/poe/ansible-runner-cve-2021-4041
  if isinstance(cmd, str):
    res = check_code_injection_match(cmd, check_unquoted=True)
    if res is not None:
      # if shell arg is true and string is tainted and unquoted that's a
      # definite code injection.
      if arg_shell is True:
        sanlib.abort_with_issue('Code injection in Popen', 'Command injection')

      # It's a maybe: will not report this to avoid false positives.
      # TODO: add more precise detection here.

  # Check for hg command injection
  # Example: tests/poe/libvcs-cve-2022-21187
  if cmd[0] == 'hg':
    # Check if the arguments are controlled by the fuzzer, and this given
    # arg is not preceded by --
    found_dashes = False
    for idx in range(1, len(cmd)):
      if cmd[0] == '--':
        found_dashes = True
      if not found_dashes and check_code_injection_match(cmd[idx]):
        sanlib.abort_with_issue(
            'command injection likely by way of mercurial. The following'
            f'command {str(cmd)} is executed, and if you substitute {cmd[idx]} '
            'with \"--config=alias.init=!touch HELLO_PY\" then you will '
            'create HELLO_PY', 'Command injection')


def hook_pre_exec_os_system(cmd):
  """Hook for os.system."""
  res = check_code_injection_match(cmd)
  if res is not None:
    sanlib.abort_with_issue(f'code injection by way of os.system\n{res}',
                            'Command injection')


def hook_pre_exec_eval(cmd):
  """Hook for eval. Experimental atm."""
  res = check_code_injection_match(cmd, check_unquoted=True)
  if res is not None:
    sanlib.abort_with_issue(f'Potential code injection by way of eval\n{res}',
                            'Command injection')
