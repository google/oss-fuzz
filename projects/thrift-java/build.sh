#!/bin/bash -eu
# Copyright 2025 Google LLC
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

export ASAN_OPTIONS=detect_leaks=0

# Build and install the compiler (disable other languages to save time)
./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=no --with-java=yes --with-nodejs=no --with-dotnet=no --with-kotlin=no
make -j$(nproc)
make install

# Build Java library and fuzzers
pushd lib/java
make check
cp build/libs/*.jar $OUT/

# Dynamically find the built jar files to be version-agnostic
MAIN_JAR=$(find build/libs -name "libthrift-*.jar" -not -name "*-test.jar" -not -name "*-sources.jar" -not -name "*-javadoc.jar" | head -n1 | xargs basename)
TEST_JAR=$(find build/libs -name "libthrift-*-test.jar" | head -n1 | xargs basename)

# Verify jars were found
if [[ -z "$MAIN_JAR" || -z "$TEST_JAR" ]]; then
  echo "Error: Could not find required jar files"
  echo "Main jar: $MAIN_JAR"
  echo "Test jar: $TEST_JAR"
  echo "Available jars:"
  find build/libs -name "*.jar"
  exit 1
fi

PROJECT_JARS="$MAIN_JAR $TEST_JAR"
echo "Using jars: $PROJECT_JARS"

RUNTIME_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# Package each fuzzer
for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
export JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
export PATH=$JAVA_HOME/bin:$PATH
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=org.apache.thrift.test.fuzz.$fuzzer_basename \
--jvm_args=\"\$mem_settings:-Djava.awt.headless=true\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
popd 