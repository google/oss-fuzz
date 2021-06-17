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

import fuzz_target


def run_coverage_command():
  fuzz_target.get_base_docker_run_command()


def generate_coverage_report(fuzz_target_paths, out_dir, clusterfuzz_deployment,
                             config):
  download_corpora(fuzz_target_paths, clusterfuz_deployment)
  run_coverage_command()
