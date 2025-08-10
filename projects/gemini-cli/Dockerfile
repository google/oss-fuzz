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

# Gemini CLI OSS-Fuzz Dockerfile (Go mirrored-parsers approach)
# Base image for Go projects
FROM gcr.io/oss-fuzz-base/base-builder-go

# Project name used by helper.py
ENV PROJECT=gemini-cli

# Set up working directory inside container
WORKDIR /root

WORKDIR /src

# Copy build script to expected location
COPY build.sh /src/build.sh

# Copy our project sources under /src/gemini-cli (build context is projects/gemini-cli)
RUN mkdir -p /src/gemini-cli
COPY . /src/gemini-cli

# Build is delegated to build.sh via helper.py, which calls:
#   bash -eux /src/gemini-cli/build.sh
# No build steps here; keep Dockerfile minimal for faster iteration.
