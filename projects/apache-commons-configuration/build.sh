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

# Moving the corpora and dictionaries to $OUT
mv $SRC/{*.zip,*.dict} $OUT

# Building the library
MAVEN_ARGS="--no-transfer-progress -Dmaven.test.skip=true -Djavac.src.version=15 -Djavac.target.version=15 -Djdk.version=15"

CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
-Dexpression=project.version -q -DforceStdout)

## maven-shade-plugin is for packaging all the dependencies into one .jar
$MVN clean package org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade $MAVEN_ARGS
cp "target/commons-configuration2-$CURRENT_VERSION.jar" "$OUT/commons-configuration.jar"

ALL_JARS="commons-configuration.jar"

## The classpath at build-time includes the project jars in $OUT as well as the Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

## All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -iname '*Fuzzer.java'); do
    fuzzer_basename=$(basename -s .java $fuzzer)
    javac -cp $BUILD_CLASSPATH $fuzzer
    cp $SRC/$fuzzer_basename.class $OUT/

    # Create an execution wrapper that executes Jazzer with the correct arguments.
    echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"-Xmx2048m:-Djava.awt.headless=true\" \
\$@" > $OUT/$fuzzer_basename

    # Make the execution wrapper executable
    chmod +x $OUT/$fuzzer_basename
done
