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
"""Utilities for scripts from gcr.io/oss-fuzz-base/base-runner."""

import os

import config_utils


def get_env(config, workspace):
  """Returns a dictionary containing the current environment with additional env
  vars set to values needed to run a fuzzer."""
  env = os.environ.copy()
  env['SANITIZER'] = config.sanitizer
  env['FUZZING_LANGUAGE'] = config.language
  env['OUT'] = workspace.out
  env['CIFUZZ'] = 'True'
  env['FUZZING_ENGINE'] = config_utils.DEFAULT_ENGINE
  env['ARCHITECTURE'] = config.architecture
  # Do this so we don't fail in tests.
  env['FUZZER_ARGS'] = '-rss_limit_mb=2560 -timeout=25'
  return env
