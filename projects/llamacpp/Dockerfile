# Copyright 2024 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake xxd
RUN git clone https://github.com/ggerganov/llama.cpp
WORKDIR $SRC/llama.cpp
# Avoid function that forks + starts instance of gdb.
# Remove statefulness during fuzzing.
# Patch callocs to avoid allocating large chunks.
# Patch a potentially unbounded loop that causes timeouts
RUN sed -i 's/ggml_print_backtrace();//g' ./ggml/src/ggml.c && \
    sed -i 's/static bool is_first_call/bool is_first_call/g' ./ggml/src/ggml.c && \
    sed -i 's/ggml_calloc(size_t num, size_t size) {/ggml_calloc(size_t num, size_t size) {\nif ((num * size) > 9000000) {GGML_ABORT("calloc err");}\n/g' ./ggml/src/ggml.c && \
    sed -i 's/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);\nif (!ok) {fclose(file); gguf_free(ctx); return NULL;}/g' ./ggml/src/ggml.c

COPY build.sh $SRC/
COPY fuzzers $SRC/llama.cpp/fuzzers
