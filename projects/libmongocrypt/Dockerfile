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

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    libssl-dev

# Clone the repository
RUN git clone --branch master --depth 1 https://github.com/mongodb/libmongocrypt.git libmongocrypt

# Set working directory
WORKDIR $SRC/libmongocrypt

# Copy build script
COPY build.sh $SRC/

