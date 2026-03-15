# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS.

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake ninja-build && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/hadipra5/weavebundle.git $SRC/weavebundle

WORKDIR $SRC/weavebundle

COPY build.sh $SRC/