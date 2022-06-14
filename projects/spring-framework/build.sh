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

cp -r "/usr/lib/jvm/java-17-openjdk-amd64/." "$JAVA_HOME" || true

cat > patch.diff <<- EOM
diff --git a/spring-core/spring-core.gradle b/spring-core/spring-core.gradle
index d9ce720..dc4e1c6 100644
--- a/spring-core/spring-core.gradle
+++ b/spring-core/spring-core.gradle
@@ -3,6 +3,7 @@ import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
 description = "Spring Core"
 
 apply plugin: "kotlin"
+apply plugin: 'com.github.johnrengelman.shadow'
 
 // spring-core includes asm, javapoet and repackages cglib, inlining all into the
 // spring-core jar. cglib itself depends on asm and is therefore further transformed by
EOM

git apply patch.diff

CURRENT_VERSION=$(./gradlew properties --console=plain | sed -nr "s/^version:\ (.*)/\1/p")

./gradlew build -x test -i -x javadoc
./gradlew shadowJar --build-file spring-core/spring-core.gradle -x javadoc
cp "spring-core/build/libs/spring-core-$CURRENT_VERSION-all.jar" "$OUT/spring-core.jar"
cp "spring-web/build/libs/spring-web-$CURRENT_VERSION.jar" "$OUT/spring-web.jar"

ALL_JARS="spring-web.jar spring-core.jar"

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
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done 