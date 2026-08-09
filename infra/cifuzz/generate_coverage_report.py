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
"""Module for generating coverage reports."""
import os

import base_runner_utils
import fuzz_target
import utils


def run_coverage_command(config, workspace):
  """Runs the coverage command in base-runner to generate a coverage report."""
  env = base_runner_utils.get_env(config, workspace)
  env['HTTP_PORT'] = ''
  env['COVERAGE_EXTRA_ARGS'] = ''
  env['CORPUS_DIR'] = workspace.corpora
  env['COVERAGE_OUTPUT_DIR'] = workspace.coverage_report
  command = 'coverage'
  return utils.execute(command, env=env)


def download_corpora(fuzz_target_paths, clusterfuzz_deployment):
  """Downloads corpora for fuzz targets in |fuzz_target_paths| using
  |clusterfuzz_deployment| to download corpora from ClusterFuzz/OSS-Fuzz."""
  for target_path in fuzz_target_paths:
    target_name = os.path.basename(target_path)
    corpus_dir = fuzz_target.get_fuzz_target_corpus_dir(
        clusterfuzz_deployment.workspace, target_name)
    clusterfuzz_deployment.download_corpus(target_name, corpus_dir)


def generate_coverage_report(fuzz_target_paths, workspace,
                             clusterfuzz_deployment, config):
  """Generates a coverage report using Clang's source based coverage."""
  download_corpora(fuzz_target_paths, clusterfuzz_deployment)
  run_coverage_command(config, workspace)
  clusterfuzz_deployment.upload_coverage()
