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


ALL_JARS=""

pushd "${SRC}/groovy"
  ./gradlew shadowJar --info
  JAR_PATH=$(find ./build/libs/ -name "groovy-*.jar" | head -n 1)
  if [[ -f $JAR_PATH ]]; then
    cp -v "$JAR_PATH" "$OUT/groovy.jar"
    ALL_JARS="${ALL_JARS} groovy.jar"
  else
    echo "Error: No JAR file found in ./build/libs/"
    exit 1
  fi


  if ls ./subprojects/groovy-test/build/libs/groovy-test-*-SNAPSHOT-all.jar 1> /dev/null 2>&1; then
    cp -v ./subprojects/groovy-test/build/libs/groovy-test-*-SNAPSHOT-all.jar "$OUT/groovy-test.jar"
    ALL_JARS="${ALL_JARS} groovy-test.jar"
  else
    echo "Error: ./subprojects/groovy-test/build/libs/groovy-test-*-SNAPSHOT-all.jar not found"
    exit 1
  fi
popd

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# compile all java files and copy them to $OUT
javac -cp $SRC:$BUILD_CLASSPATH -g $SRC/*.java
cp $SRC/*.class $OUT/

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
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
