#!/usr/bin/env python3
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

# How to use:
# This script acts as a simple filter for build logs.
# It only prints lines that match a predefined set of patterns
# (like compile/link commands, errors, and warnings).
# It also sanitizes the output by replacing SHA-1 hashes with "<hash>".
#
# Example usage for a given <command>:
#   <command> 2>&1 | ./filter_terminal.py
#
# Note that `2>&1 |` is an important part of the use of filter_terminal.py.
#
# `2>&1` is a shell redirection that says: "Redirect stream 2 (stderr) to the
# same place as stream 1 (stdout)." This effectively merges the error messages
# and the normal messages into a single stream coming out of the command's
# stdout.
# The pipe character takes the combined stream from the command on the left
# and "pipes" it directly into the `stdin` (standard input) of the command on
# the right (this script).
#
# This setup is why our Python script only needs to read from `sys.stdin`.
# The shell has already done the hard work of gathering all the relevant
# output and delivering it to us in one place.

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


if __name__ == "__main__":
  try:
    filter_log()
  except KeyboardInterrupt:
    print("\nFilter interrupted by user.")
    sys.exit(1)
