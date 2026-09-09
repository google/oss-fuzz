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
FROM gcr.io/oss-fuzz-base/base-builder
# ijar is plain C++ (only needs zlib for the zip path, not for StripClass), so
# we compile the fuzz target directly in build.sh rather than via the full
# Bazel build — minimal, hermetic, and robust across Bazel revisions.
RUN git clone --depth 1 https://github.com/bazelbuild/bazel.git $SRC/bazel
COPY ijar_strip_fuzzer.cc build.sh $SRC/
COPY ijar_strip_fuzzer_seed_corpus $SRC/ijar_strip_fuzzer_seed_corpus
WORKDIR $SRC/bazel
