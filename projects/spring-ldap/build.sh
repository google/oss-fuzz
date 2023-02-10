#!/bin/bash
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

cat > add-shadow.diff <<- EOM
diff --git a/core/build.gradle b/core/build.gradle
index d6119e9..1ffa9a1 100644
--- a/core/build.gradle
+++ b/core/build.gradle
@@ -1,6 +1,7 @@
 plugins {
     id 'io.spring.convention.spring-module'
     id 'com.intershop.gradle.javacc'
+    id 'com.github.johnrengelman.shadow' version '7.0.0'
 }

 javacc {
@@ -54,4 +55,4 @@ compileTestJava {

 test {
     jvmArgs '--add-exports', 'java.naming/com.sun.jndi.ldap=ALL-UNNAMED'
-}
\ No newline at end of file
+}
EOM

git apply add-shadow.diff

./gradlew shadowJar -p core -x test -x javadoc -x :checkstyleNohttp
CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain | sed -nr "s/^version:\ (.*)/\1/p")
cp "core/build/libs/spring-ldap-core-$CURRENT_VERSION-all.jar" "$OUT/spring-ldap-core.jar"

ALL_JARS="spring-ldap-core.jar"

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
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
LD_LIBRARY_PATH=\"\$this_dir/open-jdk-17/lib/server\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
