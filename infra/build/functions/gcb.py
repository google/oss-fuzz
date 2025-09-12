# Copyright 2022 Google LLC
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
"""Entrypoint for CI into trial_build. This script simply passes arguments from
the GCB step to the trial_build.py script."""

import logging
import os
import sys

import trial_build


def main():
  """Entrypoint for GitHub CI into trial_build.py"""
  logging.basicConfig(level=logging.INFO)

  # Get the command line arguments passed from the cloudbuild.yaml step.
  args = sys.argv[1:]

  # Append the repo and branch from the environment variables, as trial_build
  # expects them.
  args.extend(['--repo', os.environ['REPO']])
  args.extend(['--branch', os.environ['BRANCH']])

  logging.info('Passing command to trial_build: %s', args)

  if trial_build.trial_build_main(args, local_base_build=False):
    return 0
  return 1


if __name__ == '__main__':
  sys.exit(main())