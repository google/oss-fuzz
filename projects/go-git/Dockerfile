# Copyright 2023 Google LLC
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
ENV ORG_ROOT="${GOPATH}/src/github.com/go-git"

RUN mkdir -p "${ORG_ROOT}"

# The fuzzed components are scattered around multiple repositories.
# Here we clone all of them and cache their go dependencies.
# The build process happens as build.sh iterate over each one of them.
ARG REPOSITORIES="go-git go-billy"
RUN for repo in ${REPOSITORIES}; do \
    git clone --depth 1 "https://github.com/go-git/${repo}" "${ORG_ROOT}/${repo}"; \
    cd "${ORG_ROOT}/${repo}"; \
    go mod download; \
    cd -; \
    done

# Install go imports as the import section needs to reflect some of the changes
# made by build.sh.
RUN go install golang.org/x/tools/cmd/goimports@latest

COPY build.sh $SRC/
WORKDIR $SRC
