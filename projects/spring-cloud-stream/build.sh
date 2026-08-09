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

# Remove all logging to console
touch empty-logback.xml
find . -name logback.xml -exec cp empty-logback.xml "{}" \;

MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 -DskipTests -Dcheckstyle.skip=true"
CURRENT_VERSION=$(./mvnw org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout | tail -n1)

./mvnw package $MAVEN_ARGS
./mvnw package org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade $MAVEN_ARGS -f binders/rabbit-binder/spring-cloud-stream-binder-rabbit/pom.xml
cp "binders/rabbit-binder/spring-cloud-stream-binder-rabbit/target/spring-cloud-stream-binder-rabbit-$CURRENT_VERSION.jar" "$OUT/spring-cloud-stream-binder-rabbit.jar"
cp "core/spring-cloud-stream/target/spring-cloud-stream-$CURRENT_VERSION.jar" "$OUT/spring-cloud-stream.jar"

# Mockito dependencies
wget https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy/1.12.17/byte-buddy-1.12.17.jar -O "$OUT/byte-buddy.jar"
wget https://repo1.maven.org/maven2/org/objenesis/objenesis/3.3/objenesis-3.3.jar -O "$OUT/objenesis.jar"
wget https://repo1.maven.org/maven2/org/mockito/mockito-core/4.7.0/mockito-core-4.7.0.jar -O "$OUT/mockito.jar"
wget https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.12.17/byte-buddy-agent-1.12.17.jar -O "$OUT/byte-buddy-agent.jar"

ALL_JARS="spring-cloud-stream-binder-rabbit.jar spring-cloud-stream.jar mockito.jar byte-buddy.jar byte-buddy-agent.jar objenesis.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer --release 17
  cp $SRC/*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
JAVA_OPTS=\"-Dlogging.level.root=WARN -javaagent:\$this_dir/byte-buddy-agent.jar\" \
LD_LIBRARY_PATH=\"\$this_dir/open-jdk-17/lib/server\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--instrumentation_includes=org.springframework.** \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done