# Copyright 2022 Google LLC
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

ENV PROJECT_ROOT="${GOPATH:-/root/go}/src/github.com/openyurtio"

RUN mkdir -p "${PROJECT_ROOT}"

ARG REPOSITORY_OWNER="openyurtio"
ARG REPOSITORIES="yurt-app-manager"

RUN for repo in ${REPOSITORIES}; do git clone --depth 1 "https://github.com/${REPOSITORY_OWNER}/${repo}" "${PROJECT_ROOT}/${repo}"; done
RUN git clone --depth 1 https://github.com/cncf/cncf-fuzzing

COPY build.sh $SRC/
RUN chmod +x $SRC/build.sh

RUN echo "PROJECT_ROOT: $PROJECT_ROOT"
RUN echo "WORKDIR: $SRC"

WORKDIR $SRC
