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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libclang-dev \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/OSGeo/grass-addons.git /src/grass-addons

WORKDIR /src/grass-addons

COPY build.sh $SRC/

RUN chmod +x $SRC/build.sh

ENV FUZZING_ENGINE=libfuzzer
ENV SANITIZER=address  # or undefined, memory based on what you need
ENV ARCH=x86_64       # or i386 depending on your build requirements

ENTRYPOINT ["/src/build.sh"]