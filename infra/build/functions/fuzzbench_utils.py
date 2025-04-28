#!/usr/bin/env python3
#
# Copyright 2023 Google LLC
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
"""Utilities for fuzzbench runs on Google Cloud Build."""
import os
import sys

infra_dir = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(infra_dir, 'cifuzz'))
import clusterfuzz_deployment
import config_utils


def get_latest_libfuzzer_build_url(project_name):
  # Needed environment variables
  os.environ['CIFUZZ_TEST'] = 'non_falsy_str'
  os.environ['OSS_FUZZ_PROJECT_NAME'] = project_name
  config = config_utils.RunFuzzersConfig()
  deployment = clusterfuzz_deployment.OSSFuzz(config, None)
  latest_build_filename = deployment.get_latest_build_name()

  return f'gs://clusterfuzz-builds/{project_name}/' + latest_build_filename
