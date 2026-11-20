#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build with JDK 25, the fuzzers run on the JDK of the image.
MVN_JDK25="env JAVA_HOME=$SRC/jdk25 $MVN"
$MVN_JDK25 -pl main package dependency:copy-dependencies -Dmaven.test.skip=true -DincludeScope=runtime \
  -DoutputDirectory=$OUT/dependencies
current_version=$($MVN_JDK25 -pl main org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
-Dexpression=project.version -q -DforceStdout)
cp "target/kryo-$current_version.jar" $OUT/kryo.jar

# Kryo 5 needs reflectasm, objenesis and minlog at runtime, Kryo 6 has no required dependencies.
ALL_JARS="kryo.jar $(cd $OUT && ls dependencies/*.jar | tr '\n' ' ')"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac --enable-preview --release 17 -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
  cp $SRC/${fuzzer_basename}\$SomeClass.class $OUT/

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
--jvm_args=\"\$mem_settings:--enable-preview\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
