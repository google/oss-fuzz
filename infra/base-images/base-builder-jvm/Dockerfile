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

FROM gcr.io/oss-fuzz-base/base-builder

ENV JAVA_HOME /usr/lib/jvm/java-15-openjdk-amd64
ENV JVM_LD_LIBRARY_PATH $JAVA_HOME/lib/server
ENV PATH $PATH:$JAVA_HOME/bin
ENV JAZZER_API_PATH "/usr/local/lib/jazzer_api_deploy.jar"

RUN install_java.sh