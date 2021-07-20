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

import helper
import docker


def run_coverage_command(workspace, config):
  """Runs the coverage command in base-runner to generate a coverage report."""
  docker_args, _ = docker.get_base_docker_run_args(workspace, config.sanitizer,
                                                   config.language)
  docker_args += [
      '-e', 'COVERAGE_EXTRA_ARGS=', '-e', 'HTTP_PORT=', '-e',
      f'COVERAGE_OUTPUT_DIR={workspace.coverage_report}', '-t',
      docker.BASE_RUNNER_TAG, 'coverage'
  ]
  return helper.docker_run(docker_args)


def download_corpora(fuzz_target_paths, clusterfuzz_deployment):
  """Downloads corpora for fuzz targets in |fuzz_target_paths| using
  clusterfuzz_deployment| to download corpora from ClusterFuzz/OSS-Fuzz."""
  # TODO(metzman): Download to /corpus dir.
  for target_path in fuzz_target_paths:
    target = os.path.basename(target_path)
    clusterfuzz_deployment.download_corpus(target)


def generate_coverage_report(fuzz_target_paths, workspace,
                             clusterfuzz_deployment, config):
  """Generates a coverage report using Clang's source based coverage."""
  download_corpora(fuzz_target_paths, clusterfuzz_deployment)
  run_coverage_command(workspace, config)
  clusterfuzz_deployment.upload_coverage()
