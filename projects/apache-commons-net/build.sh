#!/bin/bash -eu
# Copyright 2024 Google LLC
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

MAVEN_ARGS="-Dpropguard.skip -DskipTests -Dmaven.javadoc.skip=true -Dpmd.skip=true \
  -Dencoding=UTF-8 -Dmaven.antrun.skip=true -Dcheckstyle.skip=true \
  -DperformRelease=True"
$MVN clean package $MAVEN_ARGS org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)
find ./ -name "commons-net-$CURRENT_VERSION.jar" -exec mv {} $OUT/commons-net.jar \;

ALL_JARS="commons-net.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

javac -cp $BUILD_CLASSPATH ${SRC}/*.java
install ${SRC}/*.class ${OUT}/

for fuzzer in $(find $SRC -name '*Fuzzer.java' -maxdepth 1); do
  fuzzer_basename=$(basename -s .java $fuzzer)

# Create an execution wrapper that executes Jazzer with the correct arguments.
echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
