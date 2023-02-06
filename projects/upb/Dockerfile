# Copyright 2020 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:a723398a016b23d0e2b29f5c0203a6734900e404d09fdd44a555c1514ca513fa

RUN apt-get update && apt-get install python -y
RUN git clone --depth 1 https://github.com/protocolbuffers/upb.git upb
WORKDIR upb
COPY build.sh $SRC/
