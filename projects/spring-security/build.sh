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

CURRENT_VERSION=$(sed -nr "s/^version=(.*)/\1/p" gradle.properties)

GRADLE_ARGS="-x test -x javadoc"

./gradlew shadowJar $GRADLE_ARGS -b ldap/spring-security-ldap.gradle
./gradlew shadowJar $GRADLE_ARGS -b config/spring-security-config.gradle
./gradlew shadowJar $GRADLE_ARGS -b core/spring-security-core.gradle
./gradlew build -b dependencies/spring-security-dependencies.gradle
./gradlew shadowJar $GRADLE_ARGS -b messaging/spring-security-messaging.gradle
./gradlew shadowJar $GRADLE_ARGS -b web/spring-security-web.gradle
./gradlew shadowJar $GRADLE_ARGS -b test/spring-security-test.gradle
./gradlew shadowJar $GRADLE_ARGS -b oauth2/oauth2-core/spring-security-oauth2-core.gradle
./gradlew shadowJar $GRADLE_ARGS -b acl/spring-security-acl.gradle
./gradlew shadowJar $GRADLE_ARGS -b oauth2/oauth2-client/spring-security-oauth2-client.gradle
./gradlew shadowJar $GRADLE_ARGS -b oauth2/oauth2-jose/spring-security-oauth2-jose.gradle

# Copy all shadow jars to the $OUT folder
find . -name "*-all.jar" -print0 | while read -d $'\0' file
do
    file_name=`echo $file | sed "s/-$CURRENT_VERSION-all//g" | egrep "[^\/]*.jar" -o`
    cp $file $OUT/$file_name
done

ALL_JARS=`ls $OUT/*.jar -I jazzer_agent_deploy.jar -1 | tr "\n" " " | egrep "[^\/]*.jar" -o`

# The class path at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer --release 17
  cp $SRC/[$fuzzer_basename]*.class $OUT/

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
--instrumentation_excludes=com.unboundid.ldap.**:org.springframework.ldap.** \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done

cp $SRC/StrictHttpFirewallFuzzer\$Header.class $OUT/
