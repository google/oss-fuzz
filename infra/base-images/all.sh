#!/bin/bash -eux
# Copyright 2016 Google Inc.
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

docker build --pull -t gcr.io/oss-fuzz-base/base-image "$@" infra/base-images/base-image
docker build -t gcr.io/oss-fuzz-base/base-clang "$@" infra/base-images/base-clang
docker build -t gcr.io/oss-fuzz-base/base-builder "$@" infra/base-images/base-builder
docker build -t gcr.io/oss-fuzz-base/base-builder-go "$@" infra/base-images/base-builder-go
docker build -t gcr.io/oss-fuzz-base/base-builder-jvm "$@" infra/base-images/base-builder-jvm
docker build -t gcr.io/oss-fuzz-base/base-builder-python "$@" infra/base-images/base-builder-python
docker build -t gcr.io/oss-fuzz-base/base-builder-rust "$@" infra/base-images/base-builder-rust
docker build -t gcr.io/oss-fuzz-base/base-builder-swift "$@" infra/base-images/base-builder-swift
docker build -t gcr.io/oss-fuzz-base/base-runner "$@" infra/base-images/base-runner
docker build -t gcr.io/oss-fuzz-base/base-runner-debug "$@" infra/base-images/base-runner-debug
