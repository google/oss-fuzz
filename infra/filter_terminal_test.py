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

import io
import sys
import unittest
from unittest import mock

import filter_terminal_lib


class FilterTerminalLibTest(unittest.TestCase):
  """Tests for the filter_terminal_lib.py script."""

  def test_keeps_error_lines(self):
    """Verifies that compiler error lines are kept."""
    input_line = 'src/main.cpp:42:5: error: \'cout\' is not a member of \'std\'\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_error_lines_without_prefix(self):
    """Verifies that error lines without a file prefix are kept."""
    input_line = 'error: linker command failed with exit code 1\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_fatal_error_lines(self):
    """Verifies that fatal error lines are kept."""
    input_line = 'some/path.c:10:10: fatal error: \'missing.h\' file not found\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_warning_lines(self):
    """Verifies that compiler warning lines are kept."""
    input_line = 'src/user.cpp:15:10: warning: unused variable \'user_id\' [-Wunused-variable]\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_warning_lines_without_prefix(self):
    """Verifies that warning lines without a file prefix are kept."""
    input_line = 'warning: some flag is deprecated [-Wdeprecated-flags]\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_note_lines(self):
    """Verifies that compiler 'note:' lines are kept."""
    input_line = '/usr/include/c++/11/bits/basic_string.h:111:7: note: \'std::basic_string<...>\' is not a class, struct, or union type\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_note_lines_without_prefix(self):
    """Verifies that note lines without a file prefix are kept."""
    input_line = 'note: candidate function not viable\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_instantiated_from_lines(self):
    """Verifies that 'instantiated from' context lines are kept."""
    input_line = 'src/main.cpp:85:23:   instantiated from here\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_required_from_lines(self):
    """Verifies that 'required from' context lines are kept."""
    input_line = '/usr/include/some_template_library.hpp:50:10:   required from \'void Class<T>::func() [with T = int]\'\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_source_code_lines(self):
    """Verifies that lines showing source code with line numbers are kept."""
    input_line = '   42 |   cout << "Hello, world!" << std::endl;\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_caret_pointer_lines(self):
    """Verifies that lines with carets pointing to errors are kept."""
    input_line = '      |   ^~~~\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_keeps_caret_lines_without_pipe(self):
    """Verifies that a simple caret line without a pipe is kept."""
    input_line = '   ^\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)

  def test_removes_unrelated_build_progress(self):
    """Verifies that build progress indicators are filtered out."""
    input_line = '[ 25%] Building CXX object CMakeFiles/my_project.dir/src/main.cpp.o\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertIsNone(processed)

  def test_removes_unrelated_linker_command(self):
    """Verifies that linker commands are filtered out."""
    input_line = 'Linking CXX executable bin/my_project\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertIsNone(processed)

  def test_removes_empty_line(self):
    """Verifies that empty lines are filtered out."""
    input_line = '\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertIsNone(processed)

  def test_removes_whitespace_line(self):
    """Verifies that lines containing only whitespace are filtered out."""
    input_line = '      \n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertIsNone(processed)

  def test_replaces_sha1_hash_in_error_line(self):
    """Verifies a SHA-1 hash is replaced with '<hash>' in an error line."""
    input_line = 'path/to/file.cc:12:3: error: commit 2c192c73c215205562d93e786155239a7337a659 introduced a bug\n'
    expected_output = 'path/to/file.cc:12:3: error: commit <hash> introduced a bug\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, expected_output)

  def test_replaces_multiple_sha1_hashes_in_note_line(self):
    """Verifies multiple SHA-1 hashes are replaced in a single allowed line."""
    input_line = 'note: comparing 4b825dc642cb6eb9a060e54bf8d69288fbee4904 to a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n'
    expected_output = 'note: comparing <hash> to <hash>\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, expected_output)

  def test_does_not_replace_hash_in_filtered_line(self):
    """Verifies a hash is NOT replaced if the line is filtered out anyway."""
    input_line = 'This line has a hash 4b825dc642cb6eb9a060e54bf8d69288fbee4904 but should be filtered out.\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertIsNone(processed)

  def test_sha1_pattern_handles_word_boundaries(self):
    """Verifies the SHA1 pattern requires word boundaries and won't match a hash within a larger word."""
    # This string is 41 characters long, so it shouldn't match.
    input_line = 'error: a4b825dc642cb6eb9a060e54bf8d69288fbee4904 is not a valid hash here\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)  # Should not be replaced

  def test_sha1_pattern_handles_short_strings(self):
    """Verifies the SHA1 pattern doesn't match strings shorter than 40 chars."""
    # This string is 39 characters long.
    input_line = 'error: 4b825dc642cb6eb9a060e54bf8d69288fbee490 is too short\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)  # Should not be replaced

  def test_sha1_pattern_handles_invalid_characters(self):
    """Verifies the SHA1 pattern doesn't match strings with non-hex characters."""
    # This string contains a 'g'.
    input_line = 'error: 4b825dc642cb6eb9a060e54bf8d69288fbeeg904 is invalid\n'
    processed = filter_terminal_lib.process_line(input_line)
    self.assertEqual(processed, input_line)  # Should not be replaced

  def test_filter_log_integration(self):
    """Tests the filter_log function with multi-line input."""
    log_input = (
        '[ 10%] Building object file...\n'
        'src/main.cpp:42:5: error: \'cout\' is not a member of \'std\'\n'
        '   42 |   cout << "Hello, world!" << std::endl;\n'
        '      |   ^~~~\n'
        '\n'
        'src/user.cpp:15:10: warning: unused variable \'user_id\'\n'
        'Linking executable...\n'
        'note: previous error caused by commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n'
    )

    expected_output = (
        'src/main.cpp:42:5: error: \'cout\' is not a member of \'std\'\n'
        '   42 |   cout << "Hello, world!" << std::endl;\n'
        '      |   ^~~~\n'
        'src/user.cpp:15:10: warning: unused variable \'user_id\'\n'
        'note: previous error caused by commit <hash>\n')

    mock_stdin = io.StringIO(log_input)
    mock_stdout = io.StringIO()
    with mock.patch.object(sys, 'stdin', mock_stdin):
      with mock.patch.object(sys, 'stdout', mock_stdout):
        filter_terminal_lib.filter_log()

    self.assertEqual(mock_stdout.getvalue(), expected_output)


if __name__ == '__main__':
  unittest.main()
