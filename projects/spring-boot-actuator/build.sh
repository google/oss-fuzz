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

mkdir -p $JAVA_HOME
cp -rL "/usr/lib/jvm/java-17-openjdk-amd64/." "$JAVA_HOME" || true

<<<<<<< HEAD
./gradlew clean build -p spring-boot-project/spring-boot-actuator/

CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain | sed -nr "s/^version:\ (.*)/\1/p")
cp "spring-boot-project/spring-boot-actuator/build/libs/spring-boot-actuator-$CURRENT_VERSION.jar" "$OUT/spring-boot-actuator.jar"

# Spring core
CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain --build-file=../spring-framework/build.gradle | sed -nr "s/^version:\ (.*)/\1/p")
./gradlew build -p ../spring-framework/spring-core/ -x test -x javadoc -x :checkstyleNohttp
cp "../spring-framework/spring-core/build/libs/spring-core-$CURRENT_VERSION.jar" "$OUT/spring-core.jar"
=======
./gradlew build -x test -x intTest -i -x asciidoctor -x javadoc -x asciidoctorPdf \
-x :spring-boot-project:spring-boot-docs:zip -x :spring-boot-project:spring-boot-docs:publishMavenPublicationToMavenLocal \
-x :checkstyleNohttp

CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain | sed -nr "s/^version:\ (.*)/\1/p")
cp "spring-boot-project/spring-boot-starters/spring-boot-starter-actuator/build/libs/spring-boot-starter-actuator-$CURRENT_VERSION.jar" "$OUT/spring-boot-starter-actuator.jar"
cp "spring-boot-project/spring-boot-actuator/build/libs/spring-boot-actuator-$CURRENT_VERSION.jar" "$OUT/spring-boot-actuator.jar"
cp "spring-boot-project/spring-boot/build/libs/spring-boot-$CURRENT_VERSION.jar" "$OUT/spring-boot.jar"

# Spring core
CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain --build-file=spring-framework/build.gradle | sed -nr "s/^version:\ (.*)/\1/p")
./gradlew build --build-file=spring-framework/spring-core/spring-core.gradle -x test -x javadoc -x :checkstyleNohttp
cp "spring-framework/spring-core/build/libs/spring-core-$CURRENT_VERSION.jar" "$OUT/spring-core.jar"
>>>>>>> 0d4261be (Initial integration)

ALL_JARS="spring-boot-starter-actuator.jar spring-boot.jar spring-boot-actuator.jar spring-core.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer --release 17
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
<<<<<<< HEAD
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
if [[ \"$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
=======
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
>>>>>>> 0d4261be (Initial integration)
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
<<<<<<< HEAD
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
=======
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
>>>>>>> 0d4261be (Initial integration)
