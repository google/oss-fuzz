# Copyright 2016 Google Inc.
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

FROM jenkins
MAINTAINER mike.aizatsky@gmail.com
USER root

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get upgrade -y

# should not be newer than container's.
ENV DOCKER_ENGINE_VERSION="1.11.2-0~jessie"

# Install docker
# /var/run/docker.sock will be mounted to a host.
RUN apt-get install -y apt-transport-https ca-certificates
RUN apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
RUN echo "deb https://apt.dockerproject.org/repo debian-jessie main" > /etc/apt/sources.list.d/docker.list
RUN apt-get update
RUN apt-cache policy docker-engine
RUN apt-get install -y docker-engine=$DOCKER_ENGINE_VERSION
