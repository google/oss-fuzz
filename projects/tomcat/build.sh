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

cp -r "/usr/lib/jvm/java-11-openjdk-amd64/" "$JAVA_HOME"

$ANT
$ANT test-compile
$ANT download-compile

cd $SRC/tomcat/output/classes && jar cfv classes.jar . && mv ./classes.jar $OUT 
cd $SRC/tomcat/output/testclasses && jar cfv testclasses.jar . && mv ./testclasses.jar $OUT
cd $OUT
mkdir tmp
(cd tmp; unzip -uo ../classes.jar)
(cd tmp; unzip -uo ../testclasses.jar)
jar -cvf tomcat.jar -C tmp .
rm -rf tmp
rm classes.jar
rm testclasses.jar
cd $SRC/tomcat

cp /root/tomcat-build-libs/unboundid*/unboundid*.jar $OUT/unboundid-ldapsdk.jar

ALL_JARS="tomcat.jar unboundid-ldapsdk.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer --release 11
  cp $SRC/[$fuzzer_basename]*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk/\" \
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
-rss_limit_mb=0 \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done