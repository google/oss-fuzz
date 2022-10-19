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

mv $SRC/{*.zip,*.dict} $OUT

patch pom.xml pom.patch
export MAVEN_OPTS="-Xmx1G"
MAVEN_ARGS="-Dmaven.test.skip=true -Djavac.src.version=15 -Djavac.target.version=15"
$MVN package $MAVEN_ARGS
JETTY_VERSION=$($MVN help:evaluate -Dexpression=project.version -q -DforceStdout)
cp $SRC/jetty.project/jetty-home/target/jetty-home/lib/jetty-http-$JETTY_VERSION.jar $OUT/jetty-http.jar
cp $SRC/jetty.project/jetty-home/target/jetty-home/lib/jetty-server-$JETTY_VERSION.jar $OUT/jetty-server.jar
cp $SRC/jetty.project/jetty-home/target/jetty-home/lib/jetty-util-$JETTY_VERSION.jar $OUT/jetty-util.jar
cp $SRC/jetty.project/jetty-home/target/jetty-home/lib/jetty-io-$JETTY_VERSION.jar $OUT/jetty-io.jar
cp $SRC/jetty.project/jetty-runner/target/jetty-runner-$JETTY_VERSION.jar $OUT/jetty-runner.jar

ALL_JARS="jetty-util.jar jetty-server.jar jetty-http.jar jetty-io.jar jetty-runner.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/[$fuzzer_basename]*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
JAVA_HOME=\"\$this_dir/open-jdk/\" \
if [[ \"$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
-rss_limit_mb=0 \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
