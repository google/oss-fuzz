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
import filter_terminal_lib

if __name__ == "__main__":
  try:
    filter_terminal_lib.filter_log()
  except KeyboardInterrupt:
    print("\nFilter interrupted by user.")
    sys.exit(1)
