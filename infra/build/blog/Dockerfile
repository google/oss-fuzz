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
FROM python:3.11-bullseye

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

RUN mkdir -p hugo-bin && \
    cd hugo-bin && \
    wget https://github.com/gohugoio/hugo/releases/download/v0.126.1/hugo_extended_0.126.1_linux-amd64.tar.gz && \
    tar -xzf hugo_extended_0.126.1_linux-amd64.tar.gz

ENV PATH="${PATH}:/hugo-bin/"

RUN git clone https://github.com/luizdepra/hugo-coder hugo-coder && \
    cd hugo-coder && \
    git checkout 759cc945636473d251a28597e2007cbb7d11631d # 17th May 2024

COPY content /content
COPY hugo.toml /hugo.toml
COPY build_blog.sh /build_blog.sh
RUN /build_blog.sh

CMD exec python3 -m http.server 8011 -d /oss-fuzz-blog/page/public
