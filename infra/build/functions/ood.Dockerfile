#!/usr/bin/env python3
#
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
ARG runtime_image
FROM $runtime_image

ARG BUILD_OUT_PATH
ARG FUZZING_ENGINE
ARG FUZZ_TARGET
ARG FUZZBENCH_PATH
ARG BENCHMARK
ARG OOD_OUTPUT_CORPUS_DIR

RUN mkdir -p /ood
RUN mkdir -p /ood$FUZZBENCH_PATH

COPY ./fuzzbench_run_fuzzer.sh /ood
COPY .$BUILD_OUT_PATH /ood
COPY .$FUZZBENCH_PATH /ood$FUZZBENCH_PATH

ENV OUT=/ood
ENV FUZZING_ENGINE=$FUZZING_ENGINE
ENV FUZZ_TARGET=$FUZZ_TARGET
ENV FUZZBENCH_PATH=/ood$FUZZBENCH_PATH
ENV BENCHMARK=$BENCHMARK
ENV OOD_OUTPUT_CORPUS_DIR=$OOD_OUTPUT_CORPUS_DIR

CMD ["bash", "-c", "source /ood/fuzzbench_run_fuzzer.sh && \
     mkdir -p $OOD_OUTPUT_CORPUS_DIR && \
     cp -r $OUTPUT_CORPUS_DIR $OOD_OUTPUT_CORPUS_DIR"]
