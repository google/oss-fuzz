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

# base-builder-go carries the OSS-Fuzz Go build tooling (compile_native_go_fuzzer,
# go-118-fuzz-build, sanitizer/coverage instrumentation). It is required — a plain
# golang image would lack these and build.sh would fail.
FROM gcr.io/oss-fuzz-base/base-builder-go

# Go version is NOT pinned here on purpose: erigon's go.mod (`go`/`toolchain`
# directives) is the single source of truth, and Go's GOTOOLCHAIN=auto fetches
# the matching toolchain at build time if the base image's bundled Go is older.
# Bumping Go = editing go.mod in the erigon repo; this Dockerfile stays untouched.

RUN git clone --depth 1 https://github.com/erigontech/erigon erigon
COPY build.sh $SRC/
WORKDIR $SRC/erigon
