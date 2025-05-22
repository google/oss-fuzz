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
MVNW=./mvnw

sed -i "s/<java.version>1.6<\/java.version>/<java.version>1.7<\/java.version>/g" pom.xml

export JAVA_HOME="$OUT/open-jdk-17"
mkdir -p $JAVA_HOME
rsync -aL --exclude=*.zip "/usr/lib/jvm/java-17-openjdk-amd64/" "$JAVA_HOME"

JVM_LD_LIBRARY_PATH="${JAVA_HOME}/lib/server"

MAVEN_ARGS="-Dmaven.test.skip=true -Dmaven.repo.local=$WORK/m2"

# comment out logging from W3CPropagation.java
sed -i "s|logger\.info|\/\/logger\.info|g" spring-cloud-sleuth-brave/src/main/java/org/springframework/cloud/sleuth/brave/bridge/W3CPropagation.java

# Build the target jar.
${MVNW} clean package org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade $MAVEN_ARGS

# Is this some old maven version that used to be more verbose? It prints too much, but we only need the last line of the output containing the version
CURRENT_VERSION=$(${MVNW} -Dexec.executable="echo" -Dexec.args='${project.version}' --non-recursive exec:exec  -q -DforceStdout | tail -1)

cp "spring-cloud-sleuth-brave/target/spring-cloud-sleuth-brave-$CURRENT_VERSION.jar" $OUT/spring-sleuth-brave.jar

# The jar files containing the project (separated by spaces).
PROJECT_JARS=spring-sleuth-brave.jar

# Get the fuzzer dependencies (gson).
${MVNW} dependency:copy -Dartifact=com.google.code.gson:gson:2.8.6 -DoutputDirectory=$OUT/

# The jar files containing further dependencies of the fuzz targets (separated
# by spaces).
FUZZER_JARS=gson-2.8.6.jar
ALL_JARS="$PROJECT_JARS $FUZZER_JARS"
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):.:\$this_dir
mkdir -p $OUT/org/springframework/cloud/sleuth/brave/bridge
for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH --release 15 $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/org/springframework/cloud/sleuth/brave/bridge/

  # Create execution wrapper.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH  \
--target_class=org.springframework.cloud.sleuth.brave.bridge.$fuzzer_basename \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
