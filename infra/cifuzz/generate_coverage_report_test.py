# Copyright 2021 Google LLC
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
"""Tests for generate_coverage_report."""

import unittest
from unittest import mock

import generate_coverage_report
import test_helpers

OUT_DIR = '/outdir'
PROJECT = 'example-project'
SANITIZER = 'coverage'


class TestRunCoverageCommand(unittest.TestCase):
  """Tests run_coverage_command"""

  @mock.patch('helper.docker_run')
  def test_run_coverage_command(self, mocked_docker_run):  # pylint: disable=no-self-use
    """Tests that run_coverage_command works as intended."""
    expected_docker_args = [
        '--cap-add', 'SYS_PTRACE', '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
        'ARCHITECTURE=x86_64', '-e', 'CIFUZZ=True', '-e',
        f'SANITIZER={SANITIZER}', '-e', 'FUZZING_LANGUAGE=c++', '-v',
        f'{OUT_DIR}:/out', '-e', 'COVERAGE_EXTRA_ARGS=', '-e', 'HTTP_PORT=',
        '-t', 'gcr.io/oss-fuzz-base/base-runner', 'coverage'
    ]

    config = test_helpers.create_run_config(project_name=PROJECT,
                                            sanitizer=SANITIZER)
    generate_coverage_report.run_coverage_command(OUT_DIR, config)
    mocked_docker_run.assert_called_with(expected_docker_args)


class DownloadCorporaTest(unittest.TestCase):
  """Tests for download_corpora."""

  def test_download_corpora(self):  # pylint: disable=no-self-use
    """Tests that download_corpora works as intended."""
    clusterfuzz_deployment = mock.Mock()
    fuzz_target_paths = ['/path/to/fuzzer1', '/path/to/fuzzer2']
    expected_calls = [
        mock.call('fuzzer1', OUT_DIR),
        mock.call('fuzzer2', OUT_DIR)
    ]
    generate_coverage_report.download_corpora(OUT_DIR, fuzz_target_paths,
                                              clusterfuzz_deployment)
    clusterfuzz_deployment.download_corpus.assert_has_calls(expected_calls)
