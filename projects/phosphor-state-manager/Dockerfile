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
RUN apt-get update && apt-get install -y make autoconf automake libtool nlohmann-json3-dev zip

RUN git clone --depth 1 https://github.com/openbmc/phosphor-state-manager.git phosphor-state-manager
WORKDIR phosphor-state-manager
COPY build.sh $SRC/
COPY target_parser_fuzzer.cpp $SRC/
COPY target_parser_fuzzer.dict $SRC/
COPY mock_includes $SRC/mock_includes
