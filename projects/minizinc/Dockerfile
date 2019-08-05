# Copyright 2019 Google Inc.
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
MAINTAINER Harsil S. Patel <harsil.patel@monash.edu>
RUN apt-get update && apt-get install -y make autoconf automake libtool cmake git build-essential curl
RUN curl -L https://gitlab.com/minizinc/minizinc-afl-seed-corpus/-/archive/master/minizinc-afl-seed-corpus-master.zip -o $SRC/minizinc_fuzzer_seed_corpus.zip
RUN git clone --depth 1 --branch develop https://github.com/MiniZinc/libminizinc.git minizinc
COPY minizinc_fuzzer.cpp minizinc/
WORKDIR minizinc
COPY build.sh minizinc_fuzzer.dict minizinc_fuzzer.options $SRC/