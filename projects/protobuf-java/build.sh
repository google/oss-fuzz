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

# Get the latest protoc binary release
unset CFLAGS CXXFLAGS
mkdir -p $SRC/protobuf
VERSION=$(curl --silent --fail "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | jq -r '.tag_name' | sed 's/v//')
PROTOC_ZIP="protoc-$VERSION-linux-x86_64.zip"
curl --silent --fail -L -o "$SRC/$PROTOC_ZIP" "https://github.com/protocolbuffers/protobuf/releases/download/v$VERSION/$PROTOC_ZIP"
unzip -o $PROTOC_ZIP -d $SRC/protobuf
export PROTOC=$SRC/protobuf/bin/protoc

# Get the matching protobuf-java release (protobuf-java uses 4.x versioning for protoc vx)
JAVA_VERSION="4.$VERSION"
JAR_FILE="protobuf-java-$JAVA_VERSION.jar"
curl --silent -L -o "$SRC/$JAR_FILE" "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/$JAVA_VERSION/$JAR_FILE"
cp $JAR_FILE $OUT/protobuf-java.jar

# Compile test protos with protoc.
cd $SRC/
$PROTOC --java_out=. --proto_path=. test-full.proto
jar --create --file $OUT/test-full.jar foo/*

ALL_JARS="protobuf-java.jar test-full.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
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
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\" \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done

