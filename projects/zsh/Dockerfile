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

RUN apt-get update && apt-get install -y \
    make \
    autoconf \
    automake \
    yodl \
    texinfo \
    libncurses5-dev \
    libpcre2-dev \
    groff \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/zsh-users/zsh $SRC/zsh

COPY build.sh \
     fuzz_zsh_pattern.c \
     fuzz_zsh_math.c \
     fuzz_zsh_glob.c \
     fuzz_zsh_pattern.dict \
     fuzz_zsh_math.dict \
     fuzz_zsh_glob.dict \
     $SRC/

WORKDIR $SRC/zsh
