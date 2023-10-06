#!/bin/bash -eu
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

export JAVA_HOME="$OUT/open-jdk-17"
mkdir -p $JAVA_HOME
rsync -aL --exclude=*.zip "/usr/lib/jvm/java-17-openjdk-amd64/" "$JAVA_HOME"
JVM_LD_LIBRARY_PATH="${JAVA_HOME}/lib/server"

CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain | sed -nr "s/^version:\ (.*)/\1/p")

ALL_JARS=""

function install_shadowJar {
  ./gradlew shadowJar --build-file spring-$1/spring-$1.gradle -x javadoc -x test
  install -v "spring-$1/build/libs/spring-$1-${CURRENT_VERSION}-all.jar" "$OUT/spring-$1.jar";
  ALL_JARS="${ALL_JARS} spring-$1.jar";
}

install_shadowJar shell-core;
install_shadowJar shell-standard;
install_shadowJar shell-table;

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

function create_fuzz_targets() {
  mkdir -p $SRC/$1
  mkdir -p $OUT/$1
  javac -cp $BUILD_CLASSPATH $SRC/$1/*.java --release 17

  for fuzzer in $SRC/$1/*Fuzzer.java; do
    fuzzer_basename=$(basename -s .java $fuzzer)

    # Create an execution wrapper that executes Jazzer with the correct arguments.
    echo "#!/bin/bash
    # LLVMFuzzerTestOneInput for fuzzer detection.
    this_dir=\$(dirname \"\$0\")
    JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
    if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
      mem_settings='-Xmx1900m:-Xss900k'
    else
      mem_settings='-Xmx2048m:-Xss1024k'
    fi
    LD_LIBRARY_PATH=\"\$this_dir/open-jdk-17/lib/server\":\$this_dir \
    \$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
    --cp=$RUNTIME_CLASSPATH \
    --target_class=$fuzzer_basename \
    --jvm_args=\"\$mem_settings\" \
    \$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
  done

  cp $SRC/$1/*.class $OUT/
}

create_fuzz_targets core;
create_fuzz_targets standard;
create_fuzz_targets table;
