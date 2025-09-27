# Copyright 2025 Google LLC
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
"""
Helper script to print the official list of base images.
This script serves as the single source of truth for shell scripts,
avoiding logic duplication.
"""

import os
import sys

# Add the path to the `functions` directory to import the `base_images` module.
FUNCTIONS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'build', 'functions'))
sys.path.append(FUNCTIONS_DIR)

import base_images

for image_config in base_images.BASE_IMAGES:
  # Exclude 'base-clang-full' as it is a special case not intended for
  # the general build script.
  if image_config.name != 'base-clang-full':
    print(image_config.name)
