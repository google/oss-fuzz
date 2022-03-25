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

  def setUp(self):
    test_helpers.patch_environ(self, empty=True)

  @mock.patch('utils.execute')
  def test_run_coverage_command(self, mock_execute):  # pylint: disable=no-self-use
    """Tests that run_coverage_command works as intended."""
    config = test_helpers.create_run_config(oss_fuzz_project_name=PROJECT,
                                            sanitizer=SANITIZER)
    workspace = test_helpers.create_workspace()
    generate_coverage_report.run_coverage_command(config, workspace)
    expected_command = 'coverage'
    expected_env = {
        'SANITIZER': config.sanitizer,
        'FUZZING_LANGUAGE': config.language,
        'OUT': workspace.out,
        'CIFUZZ': 'True',
        'FUZZING_ENGINE': 'libfuzzer',
        'ARCHITECTURE': 'x86_64',
        'FUZZER_ARGS': '-rss_limit_mb=2560 -timeout=25',
        'HTTP_PORT': '',
        'COVERAGE_EXTRA_ARGS': '',
        'CORPUS_DIR': workspace.corpora,
        'COVERAGE_OUTPUT_DIR': workspace.coverage_report
    }
    mock_execute.assert_called_with(expected_command, env=expected_env)


class DownloadCorporaTest(unittest.TestCase):
  """Tests for download_corpora."""

  def test_download_corpora(self):  # pylint: disable=no-self-use
    """Tests that download_corpora works as intended."""
    clusterfuzz_deployment = mock.Mock()
    clusterfuzz_deployment.workspace = test_helpers.create_workspace()
    fuzz_target_paths = ['/path/to/fuzzer1', '/path/to/fuzzer2']
    expected_calls = [
        mock.call('fuzzer1', '/workspace/cifuzz-corpus/fuzzer1'),
        mock.call('fuzzer2', '/workspace/cifuzz-corpus/fuzzer2')
    ]
    generate_coverage_report.download_corpora(fuzz_target_paths,
                                              clusterfuzz_deployment)
    clusterfuzz_deployment.download_corpus.assert_has_calls(expected_calls)
