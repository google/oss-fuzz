# Copyright 2020 Google Inc.
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
"""Cloud functions for build infrastructure."""

import base_images
import project_sync
import request_build
import request_coverage_build


def build_project(event, context):
  """Entry point for cloud function to requesting project builds."""
  request_build.request_build(event, context)


def sync(event, context):
  """Entry point for cloud function that syncs projects from github."""
  project_sync.sync(event, context)


def build_base_images(event, context):
  """Entry point for cloud function that builds base images."""
  base_images.base_builder(event, context)


def coverage_build(event, context):
  """Entry point for cloud function to build coverage reports."""
  request_coverage_build.request_coverage_build(event, context)
