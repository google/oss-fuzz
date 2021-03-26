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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool yasm curl cmake
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo

RUN mkdir afl-testcases
RUN cd afl-testcases/ && curl https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz | tar -xz
RUN zip libjpeg_turbo_fuzzer_seed_corpus.zip afl-testcases/jpeg/full/images/* afl-testcases/jpeg_turbo/full/images/* $SRC/libjpeg-turbo/testimages/*

WORKDIR libjpeg-turbo
COPY build.sh libjpeg_turbo_fuzzer.cc $SRC/
