# Copyright 2026 Google LLC
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
"""Tests for list_images."""

import importlib.util
import os
import unittest


def _load_list_images_module():
  module_path = os.path.join(os.path.dirname(__file__), 'list_images.py')
  spec = importlib.util.spec_from_file_location('list_images', module_path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


class ListImagesTest(unittest.TestCase):

  def test_get_base_image_defs_without_importing_build_dependencies(self):
    module = _load_list_images_module()

    image_names = [
        image_config['name'] for image_config in module.get_base_image_defs()
    ]

    self.assertIn('base-image', image_names)
    self.assertIn('base-builder', image_names)
    self.assertIn('base-runner', image_names)


if __name__ == '__main__':
  unittest.main()
