# SPDX-FileCopyrightText: 2026 RAWx18 <rawx18.dev@gmail.com>
# SPDX-License-Identifier: Apache-2.0

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

FROM gcr.io/oss-fuzz-base/base-builder-python:latest@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23

# uv 0.11.25 (multi-arch: linux/amd64, linux/arm64)
COPY --from=ghcr.io/astral-sh/uv:0.11.25@sha256:1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9 /uv /uvx /bin/

RUN git clone --depth 1 https://github.com/Observal/Observal.git observal
WORKDIR $SRC/observal

# Must install into the system interpreter: compile_python_fuzzer runs the
# system PyInstaller, which resolves imports against /usr/local site-packages
# only, so anything in a virtualenv is silently omitted from the bundle.
RUN uv export --frozen --only-group fuzz --no-emit-project --no-editable -o /tmp/fuzz-requirements.txt \
    && uv pip install --system --no-cache --require-hashes -r /tmp/fuzz-requirements.txt

COPY build.sh $SRC/
