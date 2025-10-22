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
ENV DEBIAN_FRONTEND=noninteractive
ENV ASAN_OPTIONS=detect_leaks=0
RUN apt update && apt install -y cmake make
RUN git clone --depth 1 https://github.com/tjko/jpegoptim.git jpegoptim \
    && cp jpegoptim/fuzz/build.sh $SRC/
RUN for script in jpegoptim/fuzz/libjpeg_builders/*.sh; do \
        bash "$script"; \
    done
WORKDIR jpegoptim
