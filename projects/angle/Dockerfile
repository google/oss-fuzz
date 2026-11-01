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
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        lsb-release sudo pkg-config file

RUN git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH=/src/depot_tools:$PATH
WORKDIR angle
# Increased retries and added more robust fetch/sync
RUN for i in {1..20}; do fetch --nohooks angle && break || (echo "Fetch failed, retrying in 60s..." && sleep 60 && if [ $i -eq 20 ]; then exit 1; fi); done
RUN for i in {1..30}; do gclient sync --jobs 1 --no-history --shallow && break || (echo "Sync failed, retrying in 60s..." && sleep 60 && if [ $i -eq 30 ]; then exit 1; fi); done

RUN ./build/install-build-deps.sh --no-prompt

COPY build.sh *.cc fuzzer_profile $SRC/

# Add fuzzer profile
RUN cat $SRC/fuzzer_profile >> /src/angle/BUILD.gn
