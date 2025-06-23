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
#
################################################################################

import sys
import re
from typing import Optional

# A compiled regex pattern to find and replace SHA-1 hashes.
# The \b word boundaries ensure we only match full 40-character hashes.
SHA1_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")

# A list of compiled regex patterns for lines we want to KEEP.
ALLOWED_PATTERNS = (
    # Catches compiler errors. The (?:.*:\s*)? makes the "file:line: " prefix optional.
    # Example: src/main.cpp:42:5: error: 'cout' is not a member of 'std'
    # Example: error: linker command failed with exit code 1
    re.compile(r'(?:.*:\s*)?(?:fatal error|error):\s'),

    # Catches compiler warnings, making the prefix optional.
    # Example: src/user.cpp:15:10: warning: unused variable 'user_id' [-Wunused-variable]
    # Example: warning: some flag is deprecated
    re.compile(r'(?:.*:\s*)?warning:\s'),

    # Catches compiler context notes, making the prefix optional.
    # Example: /usr/include/c++/11/bits/basic_string.h:111:7: note: 'std::bas...
    # Example: note: instantiated from here
    re.compile(r'(?:.*:\s*)?note:\s'),
    re.compile(r'instantiated from'),
    re.compile(r'required from'),

    # Catches the line of code accompanying an error/warning. Example:
    #    42 |   cout << "Hello, world!" << std::endl;
    re.compile(r'^\s*\d+\s*\|'),

    # Catches lines with carets, allowing for an optional '|' character.
    # Example:       |   ^~~~
    re.compile(r'^\s*(?:\|\s*)?\^'),
)


def process_line(line: str) -> Optional[str]:
  """Processes a single log line.

    Args:
      line: The line of text from the log (including the newline character).

    Returns:
      The sanitized line if it should be kept, otherwise None.
    """
  if any(pattern.search(line) for pattern in ALLOWED_PATTERNS):
    return SHA1_PATTERN.sub("<hash>", line)
  return None


def filter_log():
  """Reads from stdin, processes each line, and prints to stdout."""
  # This only needs to read from `sys.stdin` because shell has already done
  # the work of gathering all the relevant output and delivering it to us in
  # one place via the 2>&1 command.
  for line in sys.stdin:
    processed_line = process_line(line)
    if processed_line:
      sys.stdout.write(processed_line)
