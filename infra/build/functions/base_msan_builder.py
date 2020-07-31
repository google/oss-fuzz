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
"""Cloud function to build base images on Google Cloud Builder."""
import base_images
import build_msan_libs


def base_msan_builder(event, context):
  """Cloud function to build base images."""
  del event, context
  image = f'gcr.io/{base_images.BASE_PROJECT}/msan-libs-builder'
  steps = build_msan_libs.get_steps(image)
  images = [
      f'gcr.io/{base_images.BASE_PROJECT}/base-sanitizer-libs-builder',
      image,
  ]

  base_images.run_build(steps, images)
