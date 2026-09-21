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

# autoconf and automake for autogen.sh; the base image has the rest.
RUN apt-get update && \
    apt-get install -y --no-install-recommends autoconf automake && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/ocochard/pimd.git $SRC/pimd
WORKDIR $SRC/pimd
COPY build.sh $SRC/
