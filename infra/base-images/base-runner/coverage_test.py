# Copyright 2026 Google LLC
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
"""Tests for rss_limit_mb forwarding in base-runner's coverage script.

Each case runs the real coverage script against a stub fuzz target with a
controlled $OUT and asserts which libFuzzer flags are forwarded and which
notes land in the target's coverage log. Run via pytest (presubmit) or
directly: python3 coverage_test.py."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COVERAGE = os.path.join(SCRIPT_DIR, 'coverage')

# The stub records its arguments and emulates an empty profile dump so
# run_fuzz_target's dump check returns early. The llvm-profdata/llvm-cov steps
# afterwards are expected to fail; their exit status is irrelevant. The
# LLVMFuzzerTestOneInput marker is required: with FUZZING_ENGINE set, the
# coverage script only processes files containing it.
STUB_TARGET = ('#!/usr/bin/env bash\n'
               '# LLVMFuzzerTestOneInput\n'
               'printf \'%s\\n\' "$@" > "$STUB_ARGS_FILE"\n'
               'p="${LLVM_PROFILE_FILE/\\%1m/1}"\n'
               ': > "$p"\n'
               'exit 0\n')


def _read(path):
  """Returns the contents of |path|, or '' if it does not exist."""
  if not os.path.exists(path):
    return ''
  with open(path, encoding='utf-8') as file_handle:
    return file_handle.read()


def _write(path, content):
  """Writes |content| to |path|."""
  with open(path, 'w', encoding='utf-8') as file_handle:
    file_handle.write(content)


class RssLimitForwardingTest(unittest.TestCase):
  """Runs the real coverage script with a stub target and inspects the
  arguments it forwards and the log lines it writes."""

  def run_coverage(self, options_content):
    """Runs coverage on the stub target and returns (forwarded args, log)."""
    tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    out = os.path.join(tmp, 'out')
    covout = os.path.join(tmp, 'covout')
    corpus = os.path.join(tmp, 'corpus', 'stub_target')
    os.makedirs(out)
    os.makedirs(covout)
    os.makedirs(corpus)

    stub = os.path.join(out, 'stub_target')
    _write(stub, STUB_TARGET)
    os.chmod(stub, 0o755)
    if options_content is not None:
      _write(os.path.join(out, 'stub_target.options'), options_content)
    _write(os.path.join(corpus, 'input'), 'x')

    args_file = os.path.join(tmp, 'args')
    env = os.environ.copy()
    env.update({
        'OUT': out,
        'CORPUS_DIR': os.path.dirname(corpus),
        'COVERAGE_OUTPUT_DIR': covout,
        'COVERAGE_EXTRA_ARGS': '',
        'FUZZING_LANGUAGE': 'c++',
        'FUZZING_ENGINE': 'libfuzzer',
        'GOPATH': os.path.join(tmp, 'go'),
        'STUB_ARGS_FILE': args_file,
        'PATH': SCRIPT_DIR + os.pathsep + os.environ['PATH'],
    })
    # Nonzero exit is expected (the profdata merge finds no .profdata);
    # only the forwarded arguments and log lines are under test.
    subprocess.run([COVERAGE, 'stub_target'],
                   env=env,
                   timeout=300,
                   capture_output=True,
                   check=False)

    self.assertTrue(os.path.exists(args_file), 'stub target did not run')
    log = _read(os.path.join(covout, 'logs', 'stub_target.log'))
    return _read(args_file), log

  def assert_case(self, options_content, expected_flag, log_message=None):
    """Asserts the forwarded rss flag (None for none) and the log note."""
    args, log = self.run_coverage(options_content)
    match = re.search(r'^-rss_limit_mb=\d+$', args, re.MULTILINE)
    got = match.group(0) if match else None
    self.assertEqual(got, expected_flag, f'forwarded args: {args}')
    self.assertNotIn('-max_len=4096', args)
    self.assertIn('-merge=1', args)
    self.assertIn('-timeout=100', args)
    if log_message is None:
      self.assertNotIn('rss_limit_mb', log)
    else:
      self.assertIn(log_message, log)

  def test_valid_value_forwarded(self):
    """A valid value below the ceiling is forwarded as is."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 4096\n', '-rss_limit_mb=4096')

  def test_no_options_file(self):
    """Without an .options file, libFuzzer's default is kept."""
    self.assert_case(None, None)

  def test_other_options_not_forwarded(self):
    """Options other than rss_limit_mb are not forwarded."""
    self.assert_case('[libfuzzer]\nmax_len = 4096\n', None)

  def test_combined_options_only_rss_forwarded(self):
    """Only rss_limit_mb is forwarded when other options are present."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 4096\nmax_len = 4096\n',
                     '-rss_limit_mb=4096')

  def test_malformed_value_rejected_with_message(self):
    """A non-numeric value is dropped and logged."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 4096MB\n',
                     None,
                     log_message='Ignoring rss_limit_mb=4096MB')

  def test_zero_rejected_with_message(self):
    """Zero (unlimited) is dropped and logged."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 0\n',
                     None,
                     log_message='Ignoring rss_limit_mb=0')

  def test_oversized_clamped_with_message(self):
    """A value above the ceiling is clamped and logged."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 999999\n',
                     '-rss_limit_mb=8192',
                     log_message='Clamping rss_limit_mb=999999')

  def test_leading_zero_rejected_with_message(self):
    """A leading zero is dropped and logged."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 04096\n',
                     None,
                     log_message='Ignoring rss_limit_mb=04096')

  def test_overflowing_value_rejected_with_message(self):
    """2^64 + 1 wraps to 1 in bash's (( )); it must be dropped, not clamped."""
    self.assert_case('[libfuzzer]\nrss_limit_mb = 18446744073709551617\n',
                     None,
                     log_message='Ignoring rss_limit_mb=18446744073709551617')


if __name__ == '__main__':
  unittest.main()
