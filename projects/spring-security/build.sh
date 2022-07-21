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

cat > patch.diff <<- EOM
diff --git a/ldap/spring-security-ldap.gradle b/ldap/spring-security-ldap.gradle
index c4f6c08..413b992 100644
--- a/ldap/spring-security-ldap.gradle
+++ b/ldap/spring-security-ldap.gradle
@@ -1,4 +1,9 @@
+plugins {
+	id 'com.github.johnrengelman.shadow' version '7.1.2'
+}
+
 apply plugin: 'io.spring.convention.spring-module'
+apply plugin: 'com.github.johnrengelman.shadow'
 
 dependencies {
 	management platform(project(":spring-security-dependencies"))
@@ -10,7 +15,7 @@ dependencies {
 
 	optional 'com.fasterxml.jackson.core:jackson-databind'
 	optional 'ldapsdk:ldapsdk'
-	optional "com.unboundid:unboundid-ldapsdk"
+	api "com.unboundid:unboundid-ldapsdk"
 	optional "org.apache.directory.server:apacheds-core"
 	optional "org.apache.directory.server:apacheds-core-entry"
 	optional "org.apache.directory.server:apacheds-protocol-shared"
EOM

git apply patch.diff


CURRENT_VERSION=$(./gradlew properties --no-daemon --console=plain | sed -nr "s/^version:\ (.*)/\1/p")

./gradlew build -PbuildSrc.skipTests -x test -i -x javadoc -x :spring-security-docs:api -x :spring-security-itest-ldap-embedded-none:integrationTest -x :spring-security-config:integrationTest
./gradlew shadowJar --build-file ldap/spring-security-ldap.gradle -PbuildSrc.skipTests -x test -x javadoc -x :spring-security-itest-ldap-embedded-none:integrationTest
cp "core/build/libs/spring-security-core-$CURRENT_VERSION.jar" "$OUT/spring-security-core.jar"
cp "ldap/build/libs/spring-security-ldap-$CURRENT_VERSION-all.jar" "$OUT/spring-security-ldap.jar"
cp "build/libs/spring-security-$CURRENT_VERSION.jar" "$OUT/spring-security.jar"
cp "config/build/libs/spring-security-config-$CURRENT_VERSION.jar" "$OUT/spring-security-config.jar"
cp "config/build/libs/spring-security-config-$CURRENT_VERSION-test.jar" "$OUT/spring-security-config-test.jar"

ALL_JARS="spring-security-ldap.jar spring-security-core.jar spring-security.jar spring-security-config.jar spring-security-config-test.jar"

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
LD_LIBRARY_PATH=\"\$this_dir/open-jdk-17/lib/server\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--instrumentation_excludes=com.unboundid.ldap.**:org.springframework.ldap.** \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done