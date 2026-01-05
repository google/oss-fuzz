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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

# Install Java 17 using Azul Zulu distribution, because
#
# 1. Log4j build requires Java 17, `base-builder-jvm` provides Java 15 (as of 2024-07-10)
# 2. Apache Logging Services uses Zulu[1] as the OpenJDK distribution in CI
#
# [1] https://github.com/apache/logging-parent/blob/main/.github/workflows/build-reusable.yaml#L54

# Add the Zulu APT repository
RUN apt-get update && \
    apt-get install -y gnupg ca-certificates && \
    wget -q -O - https://repos.azul.com/azul-repo.key | \
    gpg --dearmor -o /usr/share/keyrings/azul.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/azul.gpg] https://repos.azul.com/zulu/deb stable main" | \
    tee /etc/apt/sources.list.d/zulu.list


# Install Zulu 17
RUN apt-get update && \
    apt-get install -y zulu17-jdk

# Update Java-related environment variables
ENV JAVA_HOME /usr/lib/jvm/zulu17
ENV JVM_LD_LIBRARY_PATH /usr/lib/jvm/zulu17/lib/server
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/out:/usr/lib/jvm/zulu17/bin

COPY build.sh $SRC/
WORKDIR $SRC
