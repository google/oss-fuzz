# Copyright 2021 Google LLC
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

RUN git clone --depth 1 https://github.com/alexcrichton/rustc-demangle

# TODO move to base-image
RUN cargo install honggfuzz
RUN cargo install afl
RUN apt update && apt install -y build-essential binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
RUN git clone --branch buildfuzz --depth 1 https://github.com/catenacyber/targets.git

COPY build.sh $SRC/

COPY fuzz*.rs $SRC/
COPY Cargo.toml $SRC/targets/targets/
RUN mkdir -p $SRC/targets/targets/src
RUN cd $SRC/targets && ln -s fuzzer-libfuzzer fuzz
RUN cat $SRC/fuzz*.rs > $SRC/targets/targets/src/lib.rs

WORKDIR $SRC/targets
