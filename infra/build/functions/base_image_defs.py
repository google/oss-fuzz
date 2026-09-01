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
"""Dependency-light base image definitions."""

# Definitions of the base images to be built.
BASE_IMAGE_DEFS = [
    {
        'name': 'base-image'
    },
    {
        'name': 'base-clang'
    },
    {
        'name': 'base-clang-full',
        'path': 'infra/base-images/base-clang',
        'build_args': ('FULL_LLVM_BUILD=1',)
    },
    {
        'name': 'indexer'
    },
    {
        'name': 'base-builder'
    },
    {
        'name': 'base-builder-go'
    },
    {
        'name': 'base-builder-javascript'
    },
    {
        'name': 'base-builder-jvm'
    },
    {
        'name': 'base-builder-python'
    },
    {
        'name': 'base-builder-ruby'
    },
    {
        'name': 'base-builder-rust'
    },
    {
        'name': 'base-builder-swift'
    },
    {
        'name': 'base-runner'
    },
    {
        'name': 'base-runner-debug'
    },
]
