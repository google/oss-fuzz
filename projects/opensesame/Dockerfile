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
# OpenSesame on OSS-Fuzz. The submission pack is maintained in the project
# repository (tests/fuzz/clusterfuzzlite/); this Dockerfile differs from the
# in-tree ClusterFuzzLite one only in cloning the repo instead of COPYing a
# checkout, per google/oss-fuzz project conventions.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f

RUN git clone https://github.com/OpenSesame-Labs/OpenSesame $SRC/opensesame
WORKDIR $SRC/opensesame
COPY build.sh $SRC/
