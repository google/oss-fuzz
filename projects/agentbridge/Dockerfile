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

FROM gcr.io/oss-fuzz-base/base-builder-jvm@sha256:d4d8b420a4de8dcde2f2677f38b8ea4ba6f9f3bcb9773859ad3b3ca676351530

RUN git clone --depth 1 https://github.com/catatafishen/agentbridge.git /src/agentbridge
WORKDIR /src/agentbridge

COPY build.sh $SRC/
