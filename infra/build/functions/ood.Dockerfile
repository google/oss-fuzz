#!/usr/bin/env python3
#
# Copyright 2023 Google LLC
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
ARG BUILD_OUT
ARG FUZZING_ENGINE
ARG FUZZBENCH_PATH

FROM $runtime_image

RUN echo "$BUILD_OUT"

RUN mkdir -p /ood

COPY ./fuzzbench_run_fuzzer.sh /ood
COPY ./$BUILD_OUT /ood
COPY ./$FUZZBENCH_PATH /ood

ENV OUT=/ood
ENV FUZZING_ENGINE=$FUZZING_ENGINE
ENV FUZZBENCH_PATH=$FUZZBENCH_PATH

RUN ls -al .
RUN ls -al /ood

CMD ["bash", "-c", "/ood/fuzzbench_run_fuzzer.sh"]