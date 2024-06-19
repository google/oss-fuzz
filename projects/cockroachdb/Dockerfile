# Copyright 2024 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-go
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 --branch FuzzTests https://github.com/Nukitt/cockroach.git cockroach

# trying to run ./dev so need no root
#ARG USERNAME=nonroot
#ARG USER_UID=1000
#ARG USER_GID=$USER_UID
#
## Create a non-root user
#RUN groupadd --gid $USER_GID $USERNAME \
#    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

WORKDIR cockroach
COPY build.sh $SRC/