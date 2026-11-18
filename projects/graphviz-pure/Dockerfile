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

# The Rust builder: a nightly toolchain and cargo-fuzz.
# The tag is "latest" and not a digest, because OSS-Fuzz's base OS consistency
# check parses the tag of this line (infra/ci/check_base_os.py).
FROM gcr.io/oss-fuzz-base/base-builder-rust:latest

# The cargo-fuzz targets are in the repository (fuzz/), so the repository is
# what OSS-Fuzz fuzzes: its default branch is cloned and built.
RUN git clone --depth 1 https://github.com/graphviz-pure/graphviz-pure graphviz-pure

WORKDIR $SRC/graphviz-pure

COPY build.sh $SRC/
