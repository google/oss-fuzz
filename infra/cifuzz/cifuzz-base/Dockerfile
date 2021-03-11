# Copyright 2020 Google LLC
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

# Don't bother with a slimmer base image.
# When we pull base-builder to build project builder image we need to pull
# ubuntu:16.04 anyway. So in the long run we probably would waste time if
# we pulled something like alpine here instead.
FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install ca-certificates wget python3 git-core --no-install-recommends -y && \
    wget https://download.docker.com/linux/ubuntu/dists/xenial/pool/stable/amd64/docker-ce-cli_20.10.5~3-0~ubuntu-xenial_amd64.deb -O /tmp/docker-ce.deb && \
    dpkg -i /tmp/docker-ce.deb && rm /tmp/docker-ce.deb && \
    apt-get remove wget -y --purge


ENV OSS_FUZZ_ROOT=/opt/oss-fuzz
ADD . ${OSS_FUZZ_ROOT}
RUN rm -rf ${OSS_FUZZ_ROOT}/infra