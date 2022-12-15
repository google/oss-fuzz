# Copyright 2021 Google LLC
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

ENV GOPATH="${GOPATH:-/root/go}"
ENV ORG_ROOT="${ORG_ROOT:-${GOPATH}/src/github.com/fluxcd}"

RUN mkdir -p "${ORG_ROOT}"

# Flux has its components scattered around multiple repositories due to its architecture. 
# Here we clone all of them. The build process happens as build.sh iterate over each one of them.
ARG REPOSITORIES="pkg notification-controller kustomize-controller helm-controller image-reflector-controller source-controller image-automation-controller"
RUN for repo in ${REPOSITORIES}; do git clone --depth 1 "https://github.com/fluxcd/${repo}" "${ORG_ROOT}/${repo}"; done

COPY build.sh $SRC/
WORKDIR $SRC
