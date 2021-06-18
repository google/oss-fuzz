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


def run_coverage_command(out_dir, config):
  """Runs the coverage command in base-runner to generate a coverage report."""
  docker_args, _ = docker.get_base_docker_run_args(out_dir, config.sanitizer,
                                                   config.language)
  docker_args += [
      '-e', 'COVERAGE_EXTRA_ARGS=', '-e', 'HTTP_PORT=', '-t',
      docker.BASE_RUNNER_TAG, 'coverage'
  ]
  return helper.docker_run(docker_args)


def download_corpora(out_dir, fuzz_target_paths, clusterfuzz_deployment):
  """Downloads corpora to |out_dir| for the fuzz targets in |fuzz_target_paths|
  using clusterfuzz_deployment| to download corpora from ClusterFuzz/OSS-Fuzz"""
  # TODO(metzman): Download to /corpus dir.
  for target_path in fuzz_target_paths:
    target = os.path.basename(target_path)
    clusterfuzz_deployment.download_corpus(target, out_dir)


def generate_coverage_report(fuzz_target_paths, out_dir, clusterfuzz_deployment,
                             config):
  """Generates a coverage report using Clang's source based coverage."""
  download_corpora(out_dir, fuzz_target_paths, clusterfuzz_deployment)
  run_coverage_command(out_dir, config)
  # TODO(metzman): Upload this build to the filestore.
