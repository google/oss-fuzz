#!/bin/bash -eux
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

# Install OpenJDK 15 and trim its size by removing unused components.
cd /tmp
curl --silent -L -O https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz && \
mkdir -p $JAVA_HOME
tar -xz --strip-components=1 -f openjdk-15.0.2_linux-x64_bin.tar.gz --directory $JAVA_HOME && \
rm -f openjdk-15.0.2_linux-x64_bin.tar.gz
rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

# Install the latest Jazzer in $OUT.
# jazzer_api_deploy.jar is required only at build-time, the agent and the
# drivers are copied to $OUT as they need to be present on the runners.
cd $SRC/
git clone https://github.com/CodeIntelligenceTesting/jazzer && \
cd jazzer && \

git checkout b12d1ea863b336b120e192700ac11c9744af6cfd # v0.17.1
#git checkout b12132743b2c0d0def680512c0c4bcb052e20b1b # v0.22.1
cat << 'EOF' >> .bazelrc
build --java_runtime_version=local_jdk_15
build --cxxopt=-stdlib=libc++
build --linkopt=-lc++
EOF

# Hotfix: https://github.com/google/oss-fuzz/issues/11613
sed -i 's/da607faed78c4cb5a5637ef74a36fdd2286f85ca5192222c4664efec2d529bb8/a0a45349bf5d57bbefe2669225cda802c5d9ab8ea412a5e683f52bdcf3f16c65/g' ./WORKSPACE.bazel
sed -i 's/bazel-toolchain-0.6.3/toolchains_llvm-0.6.3/g' ./WORKSPACE.bazel

bazel build //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar //deploy:jazzer-api //launcher:jazzer
cp $(bazel cquery --output=files //src/main/java/com/code_intelligence/jazzer:jazzer_standalone_deploy.jar) /usr/local/bin/jazzer_agent_deploy.jar
cp $(bazel cquery --output=files //launcher:jazzer) /usr/local/bin/jazzer_driver
cp $(bazel cquery --output=files //deploy:jazzer-api) $JAZZER_API_PATH
rm -rf ~/.cache/bazel ~/.cache/bazelisk
rm -rf $SRC/jazzer
