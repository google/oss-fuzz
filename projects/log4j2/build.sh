#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

echo "<?xml version=\"1.0\" encoding=\"UTF8\"?>
<toolchains>
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>15</version>
    </provides>
    <configuration>
       <jdkHome>$JAVA_HOME</jdkHome>
    </configuration>
  </toolchain>
</toolchains>
" > $SRC/maven-toolchains.xml

MAVEN_ARGS="-Dmaven.test.skip=true --no-transfer-progress --global-toolchains $SRC/maven-toolchains.xml"
$MVN package -pl log4j-api,log4j-api-java9,log4j-core,log4j-core-java9 $MAVEN_ARGS
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)
cp "log4j-core/target/log4j-core-$CURRENT_VERSION.jar" $OUT/log4j-core.jar
cp "log4j-api/target/log4j-api-$CURRENT_VERSION.jar" $OUT/log4j-api.jar

ALL_JARS="log4j-core.jar log4j-api.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API. Additionally, include $OUT itself to pick up
# BufferedImageLuminanceSource.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH:$OUT

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
